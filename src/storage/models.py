from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Sequence


@dataclass()
class RunContext:
    """Identifiers + paths for a single CRS execution."""

    project: str
    run_id: str
    root: Path
    logs_dir: Path
    artifacts_dir: Path


@dataclass()
class BuildArtifacts:
    """Record emitted by the ProjectBuilder."""

    source_dir: Path
    build_dir: Path
    compile_commands: Path | None = None
    infer_capture: Path | None = None
    binaries: list[Path] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass()
class StaticFinding:
    """Normalized representation of a static-analysis result."""

    tool: Literal["langgraph-llm", "infer"]
    check_id: str
    file: str
    line: int
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    detail: str
    evidence_path: Path | None = None
    raw_payload: dict | None = None


@dataclass()
class StaticAnalysisBatch:
    """Aggregate of static-analysis findings + metadata."""

    project: str
    run_id: str
    findings: Sequence[StaticFinding]
    summary: str

