"""
Fuzzing Pipeline for the mini CRS.

Orchestrates the fuzzing process: build fuzzer, run libFuzzer, collect results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import RuntimeConfig, TargetProjectConfig
from ..storage.local_store import LocalRunStore
from ..storage.models import (
    BuildArtifacts,
    FuzzingBatch,
    FuzzingConfig,
    RunContext,
)
from ..tools.corpus_manager import CorpusManager
from ..tools.libfuzzer_runner import LibFuzzerRunner


class FuzzingPipeline:
    """
    Orchestrates fuzzing for a target.

    Flow:
        1. Build fuzzer binary (if not already built)
        2. Initialize corpus manager
        3. Run libFuzzer
        4. Collect and persist results
    """

    def __init__(
        self,
        runtime_config: RuntimeConfig,
        runner: Optional[LibFuzzerRunner] = None,
        store: Optional[LocalRunStore] = None,
    ) -> None:
        self.runtime = runtime_config
        self.runner = runner or LibFuzzerRunner(runtime_config)
        self.store = store

    async def execute(
        self,
        target: TargetProjectConfig,
        build: BuildArtifacts,
        run_ctx: RunContext,
        config: Optional[FuzzingConfig] = None,
        harness_override: Optional[str] = None,
    ) -> FuzzingBatch:
        """
        Execute the fuzzing pipeline.

        Args:
            target: Target project configuration
            build: Build artifacts (source dir, build dir, etc.)
            run_ctx: Run context for logging and artifacts
            config: Optional fuzzing configuration
            harness_override: Override the harness to fuzz (for multi-harness support)

        Returns:
            FuzzingBatch with results
        """
        config = config or FuzzingConfig()
        
        # Determine which harness to fuzz
        harness_path = harness_override or target.fuzz_target
        harness_name = Path(harness_path).stem

        if self.store:
            self.store.log_event(run_ctx, f"Starting fuzzing for {target.name} ({harness_name})")

        # Step 1: Build fuzzer binary for this specific harness
        fuzzer_binary = await self.runner.build_fuzzer(
            target, build, run_ctx, harness_override=harness_path
        )

        if not fuzzer_binary or not fuzzer_binary.exists():
            if self.store:
                self.store.log_event(
                    run_ctx,
                    f"Fuzzer build failed for {harness_name}. "
                    f"Ensure clang with -fsanitize=fuzzer is available.",
                )
            return FuzzingBatch(
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
                summary=f"Fuzzer build failed for {harness_name} - clang with -fsanitize=fuzzer required",
            )
        
        if self.store:
            self.store.log_event(
                run_ctx,
                f"Fuzzer binary built: {fuzzer_binary}",
            )

        # Step 2: Initialize corpus manager (separate corpus per harness)
        corpus_dir = run_ctx.artifacts_dir / "fuzzing" / f"corpus_{harness_name}"
        corpus_manager = CorpusManager(
            corpus_dir=corpus_dir,
            harness_name=harness_name,
            max_crashes_per_bucket=config.max_crashes_per_bucket,
        )
        await corpus_manager.init()

        # Add initial seeds if available
        initial_seeds_dir = build.source_dir / "seeds"
        if initial_seeds_dir.exists():
            for seed_file in initial_seeds_dir.iterdir():
                if seed_file.is_file():
                    await corpus_manager.add_seed(
                        seed_file.read_bytes(),
                        source="initial",
                    )

        # Create a simple initial seed if corpus is empty
        if corpus_manager.seed_count == 0:
            # Create a minimal seed to start fuzzing
            await corpus_manager.add_seed(b"\x00", source="initial")
            await corpus_manager.add_seed(b"\x01", source="initial")
            await corpus_manager.add_seed(b"\x02", source="initial")

        seeds_initial = corpus_manager.seed_count

        if self.store:
            self.store.log_event(
                run_ctx,
                f"Starting fuzzer with {seeds_initial} initial seeds, "
                f"max_total_time={config.max_total_time}s",
            )

        # Step 3: Run libFuzzer
        result = await self.runner.run(
            fuzzer_binary=fuzzer_binary,
            corpus_manager=corpus_manager,
            config=config,
            run_ctx=run_ctx,
        )

        seeds_final = corpus_manager.seed_count
        seeds_found = seeds_final - seeds_initial

        # Step 4: Build summary
        summary_parts = [
            f"Fuzzing completed in {result.duration_seconds:.1f}s.",
            f"Seeds: {seeds_initial} initial → {seeds_final} final (+{seeds_found} new).",
            f"Crashes found: {len(result.new_crashes)}.",
        ]

        if result.returncode != 0 and result.returncode != -1:
            summary_parts.append(f"Fuzzer exited with code {result.returncode}.")

        summary = " ".join(summary_parts)

        if self.store:
            self.store.log_event(run_ctx, summary)

        # Persist crash details
        self._persist_crash_details(run_ctx, result.new_crashes)

        return FuzzingBatch(
            project=target.name,
            run_id=run_ctx.run_id,
            harness=harness_path,
            fuzzer_binary=str(fuzzer_binary),
            duration_seconds=result.duration_seconds,
            seeds_initial=seeds_initial,
            seeds_final=seeds_final,
            seeds_found=seeds_found,
            crashes_found=len(result.new_crashes),
            crashes=result.new_crashes,
            summary=summary,
        )

    def _persist_crash_details(self, run_ctx: RunContext, crashes: list) -> None:
        """Write crash details to a log file."""
        if not crashes:
            return

        crash_log = run_ctx.artifacts_dir / "fuzzing" / "crashes.log"
        crash_log.parent.mkdir(parents=True, exist_ok=True)

        with crash_log.open("w", encoding="utf-8") as f:
            f.write(f"# Crashes found at {datetime.now(timezone.utc).isoformat()}\n\n")
            for crash in crashes:
                f.write(f"## Crash: {crash.crash_id}\n")
                f.write(f"- Dedup token: {crash.dedup_token}\n")
                f.write(f"- Signal: {crash.signal}\n")
                f.write(f"- Input size: {crash.input_size} bytes\n")
                f.write(f"- Input path: {crash.input_path}\n")
                if crash.stack_trace:
                    f.write(f"- Stack trace:\n```\n{crash.stack_trace}\n```\n")
                f.write("\n")

