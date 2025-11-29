from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from ..config import RuntimeConfig, TargetProjectConfig
from ..pipelines.static_analysis import StaticAnalysisPipeline
from ..storage.local_store import LocalRunStore
from ..storage.models import BuildArtifacts, StaticAnalysisBatch
from ..tools.project_builder import ProjectBuilder


class MiniCRSOrchestrator:
    """
    High-level coordinator for the mini CRS.

    Responsibilities:
        * Allocate workspaces per target run.
        * Invoke the project builder and ensure artifacts exist.
        * Launch static-analysis pipelines (LLM + Infer).
        * Persist normalized outputs for downstream consumers.
    """

    def __init__(
        self,
        runtime_config: RuntimeConfig,
        builder: Optional[ProjectBuilder] = None,
        static_pipeline: Optional[StaticAnalysisPipeline] = None,
        store: Optional[LocalRunStore] = None,
    ) -> None:
        self.runtime = runtime_config
        self.store = store or LocalRunStore(runtime_config.workspace_root)
        self.builder = builder or ProjectBuilder(runtime_config)
        self.static_pipeline = static_pipeline or StaticAnalysisPipeline(
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

    async def run_single_target(self, target: TargetProjectConfig) -> StaticAnalysisBatch:
        """Execute the static analysis flow for a single target."""
        run_ctx = self.store.allocate_run_context(target.name)

        async with self._lock:
            self.store.log_event(run_ctx, f"Starting run for {target.name}")

        try:
            build_artifacts: BuildArtifacts = await self.builder.prepare_target(
                target, run_ctx
            )
        except Exception as e:
            self.store.log_event(run_ctx, f"Build failed: {e}")
            # Create empty batch to persist partial results
            static_batch = StaticAnalysisBatch(
                project=target.name,
                run_id=run_ctx.run_id,
                findings=[],
                summary=f"Build failed: {e}",
            )
            self.store.persist_static_batch(run_ctx, static_batch)
            raise

        try:
            static_batch = await self.static_pipeline.execute(
                target=target, build=build_artifacts, run_ctx=run_ctx
            )
        except Exception as e:
            self.store.log_event(run_ctx, f"Static analysis failed: {e}")
            # Persist partial results even on failure
            static_batch = StaticAnalysisBatch(
                project=target.name,
                run_id=run_ctx.run_id,
                findings=[],
                summary=f"Static analysis failed: {e}",
            )
            self.store.persist_static_batch(run_ctx, static_batch)
            raise

        self.store.persist_static_batch(run_ctx, static_batch)
        self.store.log_event(
            run_ctx,
            f"Completed static analysis with {len(static_batch.findings)} findings at "
            f"{datetime.now(timezone.utc).isoformat()}",
        )
        return static_batch


def workspace_child(root: Path, *parts: str) -> Path:
    """Convenience helper used by multiple modules."""
    return root.joinpath(*parts)

