from __future__ import annotations

from pathlib import Path

from ..config import RuntimeConfig
from ..storage import LocalRunStore
from ..storage.models import StaticFinding
from ..tools.llm_client import LangGraphClient
from .base import AgentContext, BaseAgent


class StaticAnalysisAgent(BaseAgent):
    """LLM-based reasoning loop for static analysis heuristics."""

    def __init__(self, runtime_config: RuntimeConfig, store: LocalRunStore | None = None):
        self.runtime = runtime_config
        self._client = LangGraphClient(runtime_config)
        self.store = store

    async def run(self, ctx: AgentContext) -> list[StaticFinding]:
        summary, findings = await self._client.run_static_review(
            target=ctx.target,
            build=ctx.build,
            run_ctx=ctx.run_ctx,
            store=ctx.store,
        )
        (ctx.run_ctx.logs_dir / "llm_summary.txt").write_text(summary, encoding="utf-8")
        if ctx.store:
            ctx.store.log_event(ctx.run_ctx, "LLM static analysis completed")
        return list(findings)

