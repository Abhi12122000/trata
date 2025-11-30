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
    fuzzer_binary: Path | None = None  # Path to compiled fuzzer


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


# ============================================================================
# Fuzzing Models
# ============================================================================


@dataclass()
class FuzzingConfig:
    """Configuration for a fuzzing run."""

    timeout_seconds: int = 60  # Per-run timeout
    max_total_time: int = 300  # Total fuzzing time
    workers: int = 1  # Number of parallel fuzzer jobs
    detect_leaks: bool = False  # Enable leak detection
    max_crashes_per_bucket: int = 5  # Max crashes to keep per dedup bucket


@dataclass()
class FuzzCrash:
    """A crash found by the fuzzer."""

    crash_id: str  # SHA1 of input data
    input_path: Path  # Path to crash input file
    input_size: int  # Size in bytes
    dedup_token: str  # Stack hash for deduplication
    harness: str  # Name of the harness that found it
    timestamp: str  # ISO format timestamp
    stack_trace: str = ""  # Captured stack trace (if available)
    signal: str = ""  # Signal that caused crash (SIGSEGV, SIGABRT, etc.)


@dataclass()
class FuzzSeed:
    """A seed in the fuzzing corpus."""

    seed_id: str  # SHA1 of content
    path: Path  # Path to seed file
    size: int  # Size in bytes
    source: Literal["initial", "fuzzer", "llm", "corpus_match"]  # Origin


@dataclass()
class FuzzingBatch:
    """Results of a fuzzing run."""

    project: str
    run_id: str
    harness: str
    fuzzer_binary: str
    duration_seconds: float
    seeds_initial: int
    seeds_final: int
    seeds_found: int
    crashes_found: int
    crashes: Sequence[FuzzCrash]
    summary: str


@dataclass()
class CRSResult:
    """Combined result from a full CRS run."""

    project: str
    run_id: str
    static_analysis: StaticAnalysisBatch | None = None
    fuzzing: FuzzingBatch | None = None
    summary: str = ""
