from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from ..config import RuntimeConfig, TargetProjectConfig
from ..pipelines.static_analysis import StaticAnalysisPipeline
from ..pipelines.fuzzing import FuzzingPipeline
from ..storage.local_store import LocalRunStore
from ..storage.models import (
    BuildArtifacts,
    CRSResult,
    FuzzingBatch,
    FuzzingConfig,
    StaticAnalysisBatch,
)
from ..tools.crash_deduplicator import CrashDeduplicator
from ..tools.project_builder import ProjectBuilder


class MiniCRSOrchestrator:
    """
    High-level coordinator for the mini CRS.

    Responsibilities:
        * Allocate workspaces per target run.
        * Invoke the project builder and ensure artifacts exist.
        * Launch static-analysis pipelines (LLM + Infer).
        * Launch fuzzing pipeline (libFuzzer).
        * Persist normalized outputs for downstream consumers.
    """

    def __init__(
        self,
        runtime_config: RuntimeConfig,
        builder: Optional[ProjectBuilder] = None,
        static_pipeline: Optional[StaticAnalysisPipeline] = None,
        fuzzing_pipeline: Optional[FuzzingPipeline] = None,
        store: Optional[LocalRunStore] = None,
    ) -> None:
        self.runtime = runtime_config
        self.store = store or LocalRunStore(runtime_config.workspace_root)
        self.builder = builder or ProjectBuilder(runtime_config)
        self.static_pipeline = static_pipeline or StaticAnalysisPipeline(
            runtime_config=runtime_config,
            store=self.store,
        )
        self.fuzzing_pipeline = fuzzing_pipeline or FuzzingPipeline(
            runtime_config=runtime_config,
            store=self.store,
        )
        self._lock = asyncio.Lock()

    async def run_targets(self, targets: Iterable[TargetProjectConfig]) -> None:
        """Run the CRS sequentially or with limited parallelism."""
        sem = asyncio.Semaphore(self.runtime.max_parallel_jobs)

        async def _guarded_run(target: TargetProjectConfig) -> None:
            async with sem:
                await self.run_single_target(target)

        await asyncio.gather(*(_guarded_run(t) for t in targets))

    async def run_single_target(self, target: TargetProjectConfig) -> CRSResult:
        """Execute the full CRS flow for a single target."""
        run_ctx = self.store.allocate_run_context(target.name)

        async with self._lock:
            self.store.log_event(run_ctx, f"Starting run for {target.name}")

        static_batch: StaticAnalysisBatch | None = None
        fuzzing_batch: FuzzingBatch | None = None
        build_artifacts: BuildArtifacts | None = None

        # ====================================================================
        # Step 1: Build
        # ====================================================================
        try:
            build_artifacts = await self.builder.prepare_target(target, run_ctx)
        except Exception as e:
            self.store.log_event(run_ctx, f"Build failed: {e}")
            static_batch = StaticAnalysisBatch(
                project=target.name,
                run_id=run_ctx.run_id,
                findings=[],
                summary=f"Build failed: {e}",
            )
            self.store.persist_static_batch(run_ctx, static_batch)
            return CRSResult(
                project=target.name,
                run_id=run_ctx.run_id,
                static_analysis=static_batch,
                summary=f"Build failed: {e}",
            )

        # ====================================================================
        # Step 2: Static Analysis
        # ====================================================================
        try:
            static_batch = await self.static_pipeline.execute(
                target=target, build=build_artifacts, run_ctx=run_ctx
            )
            self.store.persist_static_batch(run_ctx, static_batch)
            self.store.log_event(
                run_ctx,
                f"Completed static analysis with {len(static_batch.findings)} findings",
            )
        except Exception as e:
            self.store.log_event(run_ctx, f"Static analysis failed: {e}")
            static_batch = StaticAnalysisBatch(
                project=target.name,
                run_id=run_ctx.run_id,
                findings=[],
                summary=f"Static analysis failed: {e}",
            )
            self.store.persist_static_batch(run_ctx, static_batch)
            # Continue to fuzzing even if static analysis fails

        # ====================================================================
        # Step 3: Fuzzing (if enabled) - runs on ALL harnesses
        # ====================================================================
        all_fuzzing_batches: list[FuzzingBatch] = []
        
        if self.runtime.enable_fuzzing and target.has_fuzz_targets:
            # Calculate time per harness (divide total time among harnesses)
            num_harnesses = len(target.fuzz_targets)
            time_per_harness = max(30, self.runtime.fuzzing_max_time // num_harnesses)
            
            self.store.log_event(
                run_ctx,
                f"Starting fuzzing on {num_harnesses} harness(es), "
                f"{time_per_harness}s per harness",
            )
            
            for harness_path in target.fuzz_targets:
                harness_name = Path(harness_path).stem
                self.store.log_event(run_ctx, f"Fuzzing harness: {harness_name}")
                
                try:
                    fuzzing_config = FuzzingConfig(
                        timeout_seconds=self.runtime.fuzzing_timeout,
                        max_total_time=time_per_harness,
                        workers=self.runtime.fuzzing_workers,
                    )
                    batch = await self.fuzzing_pipeline.execute(
                        target=target,
                        build=build_artifacts,
                        run_ctx=run_ctx,
                        config=fuzzing_config,
                        harness_override=harness_path,  # Override the harness
                    )
                    all_fuzzing_batches.append(batch)
                    self._persist_fuzzing_batch(run_ctx, batch, harness_name)
                    self.store.log_event(
                        run_ctx,
                        f"Completed fuzzing {harness_name}: {batch.crashes_found} crashes, "
                        f"{batch.seeds_found} new seeds",
                    )
                except Exception as e:
                    self.store.log_event(run_ctx, f"Fuzzing {harness_name} failed: {e}")
                    batch = FuzzingBatch(
                        project=target.name,
                        run_id=run_ctx.run_id,
                        harness=harness_path,
                        fuzzer_binary="",
                        duration_seconds=0,
                        seeds_initial=0,
                        seeds_final=0,
                        seeds_found=0,
                        crashes_found=0,
                        crashes=[],
                        summary=f"Fuzzing failed: {e}",
                    )
                    all_fuzzing_batches.append(batch)
                    self._persist_fuzzing_batch(run_ctx, batch, harness_name)
            
            # Aggregate results into a combined fuzzing_batch for summary
            if all_fuzzing_batches:
                total_crashes = sum(b.crashes_found for b in all_fuzzing_batches)
                total_seeds = sum(b.seeds_found for b in all_fuzzing_batches)
                total_duration = sum(b.duration_seconds for b in all_fuzzing_batches)
                all_crashes = [c for b in all_fuzzing_batches for c in b.crashes]
                
                # Deduplicate crashes by stack trace
                self.store.log_event(
                    run_ctx,
                    f"Deduplicating {len(all_crashes)} crashes by stack trace...",
                )
                dedup = CrashDeduplicator()
                unique_crashes = dedup.get_unique_crashes(all_crashes)
                dedup_summary = dedup.get_dedup_summary(all_crashes)
                
                self.store.log_event(
                    run_ctx,
                    f"Deduplication: {len(all_crashes)} → {len(unique_crashes)} unique "
                    f"({dedup_summary['reduction_ratio']*100:.1f}% reduction)",
                )
                
                # Persist deduplicated crashes
                self._persist_deduplicated_crashes(run_ctx, unique_crashes, dedup_summary)
                
                fuzzing_batch = FuzzingBatch(
                    project=target.name,
                    run_id=run_ctx.run_id,
                    harness=", ".join(target.fuzz_targets),
                    fuzzer_binary="(multiple)",
                    duration_seconds=total_duration,
                    seeds_initial=sum(b.seeds_initial for b in all_fuzzing_batches),
                    seeds_final=sum(b.seeds_final for b in all_fuzzing_batches),
                    seeds_found=total_seeds,
                    crashes_found=total_crashes,
                    crashes=all_crashes,
                    summary=f"Fuzzing {num_harnesses} harnesses: {total_crashes} crashes ({len(unique_crashes)} unique), {total_seeds} new seeds",
                )
                # Persist combined results
                self._persist_fuzzing_batch(run_ctx, fuzzing_batch, "combined")

        # ====================================================================
        # Build final summary
        # ====================================================================
        summary_parts = []
        if static_batch:
            summary_parts.append(
                f"Static analysis: {len(static_batch.findings)} findings"
            )
        if fuzzing_batch:
            summary_parts.append(
                f"Fuzzing: {fuzzing_batch.crashes_found} crashes, "
                f"{fuzzing_batch.seeds_found} new seeds"
            )

        result = CRSResult(
            project=target.name,
            run_id=run_ctx.run_id,
            static_analysis=static_batch,
            fuzzing=fuzzing_batch,
            summary=". ".join(summary_parts) if summary_parts else "No results",
        )

        self.store.log_event(
            run_ctx,
            f"CRS run completed at {datetime.now(timezone.utc).isoformat()}. {result.summary}",
        )

        return result

    def _persist_fuzzing_batch(
        self, run_ctx, batch: FuzzingBatch, harness_name: str = "fuzzing"
    ) -> None:
        """Persist fuzzing results to JSON."""
        out_file = run_ctx.artifacts_dir / "fuzzing" / f"{harness_name}_results.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "project": batch.project,
            "run_id": batch.run_id,
            "harness": batch.harness,
            "fuzzer_binary": batch.fuzzer_binary,
            "duration_seconds": batch.duration_seconds,
            "seeds_initial": batch.seeds_initial,
            "seeds_final": batch.seeds_final,
            "seeds_found": batch.seeds_found,
            "crashes_found": batch.crashes_found,
            "crashes": [
                {
                    "crash_id": c.crash_id,
                    "input_path": str(c.input_path),
                    "input_size": c.input_size,
                    "dedup_token": c.dedup_token,
                    "harness": c.harness,
                    "timestamp": c.timestamp,
                    "signal": c.signal,
                    "stack_trace": c.stack_trace[:500] if c.stack_trace else "",
                }
                for c in batch.crashes
            ],
            "summary": batch.summary,
        }

        with out_file.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def _persist_deduplicated_crashes(
        self, run_ctx, unique_crashes: list, dedup_summary: dict
    ) -> None:
        """Persist deduplicated crashes to JSON for use by patcher agent."""
        out_file = run_ctx.artifacts_dir / "fuzzing" / "deduplicated_crashes.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "total_crashes": dedup_summary["total_crashes"],
            "unique_signatures": dedup_summary["unique_signatures"],
            "reduction_ratio": dedup_summary["reduction_ratio"],
            "unique_crashes": [
                {
                    "crash_id": c.crash_id,
                    "input_path": str(c.input_path),
                    "input_size": c.input_size,
                    "dedup_token": c.dedup_token,
                    "harness": c.harness,
                    "timestamp": c.timestamp,
                    "signal": c.signal,
                    "stack_trace": c.stack_trace,  # Full stack trace for patcher
                }
                for c in unique_crashes
            ],
            "clusters": dedup_summary["clusters"],
        }

        with out_file.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        
        self.store.log_event(
            run_ctx,
            f"Saved {len(unique_crashes)} deduplicated crashes to {out_file.name}",
        )


def workspace_child(root: Path, *parts: str) -> Path:
    """Convenience helper used by multiple modules."""
    return root.joinpath(*parts)
