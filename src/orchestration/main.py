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
        # Step 3: Fuzzing (if enabled)
        # ====================================================================
        if self.runtime.enable_fuzzing and target.fuzz_target:
            try:
                fuzzing_config = FuzzingConfig(
                    timeout_seconds=self.runtime.fuzzing_timeout,
                    max_total_time=self.runtime.fuzzing_max_time,
                    workers=self.runtime.fuzzing_workers,
                )
                fuzzing_batch = await self.fuzzing_pipeline.execute(
                    target=target,
                    build=build_artifacts,
                    run_ctx=run_ctx,
                    config=fuzzing_config,
                )
                self._persist_fuzzing_batch(run_ctx, fuzzing_batch)
                self.store.log_event(
                    run_ctx,
                    f"Completed fuzzing: {fuzzing_batch.crashes_found} crashes, "
                    f"{fuzzing_batch.seeds_found} new seeds",
                )
            except Exception as e:
                self.store.log_event(run_ctx, f"Fuzzing failed: {e}")
                fuzzing_batch = FuzzingBatch(
                    project=target.name,
                    run_id=run_ctx.run_id,
                    harness=target.fuzz_target,
                    fuzzer_binary="",
                    duration_seconds=0,
                    seeds_initial=0,
                    seeds_final=0,
                    seeds_found=0,
                    crashes_found=0,
                    crashes=[],
                    summary=f"Fuzzing failed: {e}",
                )
                self._persist_fuzzing_batch(run_ctx, fuzzing_batch)

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

    def _persist_fuzzing_batch(self, run_ctx, batch: FuzzingBatch) -> None:
        """Persist fuzzing results to JSON."""
        out_file = run_ctx.artifacts_dir / "fuzzing" / "fuzzing_results.json"
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


def workspace_child(root: Path, *parts: str) -> Path:
    """Convenience helper used by multiple modules."""
    return root.joinpath(*parts)
