from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..config import TargetProjectConfig
from ..storage.models import BuildArtifacts, RunContext, StaticFinding


@dataclass()
class AgentContext:
    target: TargetProjectConfig
    build: BuildArtifacts
    run_ctx: RunContext
    store: "LocalRunStore | None" = None


class BaseAgent(Protocol):
    async def run(self, ctx: AgentContext) -> list[StaticFinding]:
        """Execute the agent and return normalized findings."""

