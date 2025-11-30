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

    # Infer settings
    infer_docker_image: str = "trata-infer:1.2.0"
    infer_docker_build_context: Optional[Path] = (
        Path(__file__).resolve().parents[1] / "docker" / "infer"
    )
    prefer_docker_infer: bool = True

    # LLM settings
    llm_budget_tokens: int = 32_000
    llm_max_files: int | None = None

    # Fuzzing settings
    enable_fuzzing: bool = True
    fuzzing_timeout: int = 60  # Per-execution timeout (seconds)
    fuzzing_max_time: int = 120  # Total fuzzing time (seconds)
    fuzzing_workers: int = 1  # Number of parallel fuzzer jobs

    storage_backend: Literal["local"] = "local"
    extra_env: dict[str, str] = field(default_factory=dict)
