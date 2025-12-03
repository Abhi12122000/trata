from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional, Sequence


@dataclass()
class TargetProjectConfig:
    """Describes a single OSS-Fuzz style target project."""

    name: str
    repo_url: str
    # fuzz_targets: list of harness source files (e.g., ["fuzz/vuln_fuzzer.c", "fuzz/packet_fuzzer.c"])
    fuzz_targets: Sequence[str] = ()
    build_system: Literal["oss-fuzz", "cmake", "autotools", "custom"] = "oss-fuzz"
    build_script: Optional[str] = None
    local_checkout: Optional[Path] = None
    commit: Optional[str] = None
    harness_globs: Sequence[str] = ()

    @property
    def fuzz_target(self) -> str:
        """Primary fuzz target (first in list) for backward compatibility."""
        return self.fuzz_targets[0] if self.fuzz_targets else ""

    @property
    def has_fuzz_targets(self) -> bool:
        """Check if any fuzz targets are configured."""
        return len(self.fuzz_targets) > 0


@dataclass()
class RuntimeConfig:
    """Global runtime knobs for the mini CRS."""

    workspace_root: Path = Path(__file__).resolve().parents[1] / "data"
    langchain_model: str = "gpt-4o-mini"
    max_parallel_jobs: int = 2
    dry_run: bool = False

    # Infer settings
    infer_docker_image: str = "trata-infer:1.2.0"
    infer_docker_build_context: Optional[Path] = (
        Path(__file__).resolve().parents[1] / "docker" / "infer"
    )
    prefer_docker_infer: bool = True

    # LLM Static Analysis settings
    llm_budget_tokens: int = 32_000
    llm_max_files: int | None = None
    enable_static_llm: bool = True  # Enable LLM-based static analysis
    static_max_findings_per_file: int = 5  # Max findings per file
    static_max_total_findings: int = 50  # Max total findings from LLM
    static_max_llm_calls: int = 20  # Max LLM calls for static analysis

    # Fuzzing settings
    enable_fuzzing: bool = True
    fuzzing_timeout: int = 60  # Per-execution timeout (seconds)
    fuzzing_max_time: int = 120  # Total fuzzing time (seconds)
    fuzzing_workers: int = 1  # Number of parallel fuzzer jobs

    # Patching settings
    enable_patching: bool = True
    patcher_model: str = "gpt-4o"  # Model for patcher LLM
    patcher_context_lines: int = 50  # Lines of context around vulnerability

    storage_backend: Literal["local"] = "local"
    extra_env: dict[str, str] = field(default_factory=dict)
