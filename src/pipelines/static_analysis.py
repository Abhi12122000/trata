from __future__ import annotations

from typing import Iterable, Optional

from ..agents import AgentContext, StaticAnalysisAgent
from ..config import RuntimeConfig, TargetProjectConfig
from ..storage import LocalRunStore
from ..storage.models import BuildArtifacts, RunContext, StaticAnalysisBatch, StaticFinding
from ..tools.fbinfer_runner import InferRunner


class StaticAnalysisPipeline:
    """Runs both deterministic and LLM-driven static analysis jobs."""

    def __init__(
        self,
        runtime_config: RuntimeConfig,
        infer_runner: Optional[InferRunner] = None,
        agents: Optional[Iterable[StaticAnalysisAgent]] = None,
        store: Optional[LocalRunStore] = None,
    ) -> None:
        self.runtime = runtime_config
        self.infer_runner = infer_runner or InferRunner(runtime_config)
        self.store = store
        self.agents = (
            list(agents)
            if agents is not None
            else [StaticAnalysisAgent(runtime_config, store=store)]
        )

    async def execute(
        self,
        target: TargetProjectConfig,
        build: BuildArtifacts,
        run_ctx: RunContext,
    ) -> StaticAnalysisBatch:
        ctx = AgentContext(
            target=target, build=build, run_ctx=run_ctx, store=self.store
        )

        llm_findings: list[StaticFinding] = []
        for agent in self.agents:
            llm_findings.extend(await agent.run(ctx))

        infer_result = await self.infer_runner.run(
            target=target,
            source_dir=build.source_dir,
            build_dir=build.build_dir,
            output_dir=run_ctx.artifacts_dir / "infer",
            compile_commands=build.compile_commands,
        )

        findings = llm_findings + list(infer_result.findings)
        summary = (
            f"{len(findings)} total findings: "
            f"{len(llm_findings)} from LangGraph agents, "
            f"{len(infer_result.findings)} from Infer."
        )

        return StaticAnalysisBatch(
            project=target.name,
            run_id=run_ctx.run_id,
            findings=findings,
            summary=summary,
        )

