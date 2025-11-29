from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional, Sequence


@dataclass()
class TargetProjectConfig:
    """Describes a single OSS-Fuzz style target project."""

    name: str
    repo_url: str
    fuzz_target: str
    build_system: Literal["oss-fuzz", "cmake", "autotools", "custom"] = "oss-fuzz"
    build_script: Optional[str] = None
    local_checkout: Optional[Path] = None
    commit: Optional[str] = None
    harness_globs: Sequence[str] = ()


@dataclass()
class RuntimeConfig:
    """Global runtime knobs for the mini CRS."""

    workspace_root: Path = Path(__file__).resolve().parents[1] / "data"
    langgraph_model: str = "gpt-4o-mini"
    max_parallel_jobs: int = 2
    dry_run: bool = False
    infer_docker_image: str = "facebook/infer:latest"
    llm_budget_tokens: int = 32_000
    llm_max_files: int | None = None
    prefer_docker_infer: bool = False
    storage_backend: Literal["local"] = "local"
    extra_env: dict[str, str] = field(default_factory=dict)

