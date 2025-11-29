from __future__ import annotations

import json
import shutil
import subprocess
import asyncio
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

from ..config import RuntimeConfig, TargetProjectConfig
from ..storage.models import StaticFinding


@dataclass()
class InferResult:
    findings: Sequence[StaticFinding]
    raw_report: Path | None = None


class InferRunner:
    """Thin wrapper around facebook/infer executed via Docker or local binary."""

    def __init__(self, runtime_config: RuntimeConfig) -> None:
        self.runtime = runtime_config

    async def run(
        self,
        target: TargetProjectConfig,
        source_dir: Path,
        build_dir: Path,
        output_dir: Path,
        compile_commands: Path | None = None,
    ) -> InferResult:
        output_dir.mkdir(parents=True, exist_ok=True)

        process: subprocess.CompletedProcess | None = None

        async def run_local() -> subprocess.CompletedProcess | None:
            infer_cmd = shutil.which("infer")
            if not infer_cmd:
                return None
            cmd = [
                infer_cmd,
                "--reactive",
                "--keep-going",
                f"--project-root={source_dir}",
                "-o",
                str(output_dir),
            ]
            cmd.extend(self._build_compilation_args(source_dir, compile_commands, local=True))
            cmd.extend(self._build_skip_args(target, source_dir))
            env = {"INFER_RESULTS_DIR": str(output_dir), **self.runtime.extra_env}
            return await asyncio_subprocess(cmd, cwd=build_dir, env=env)

        async def run_docker() -> subprocess.CompletedProcess:
            docker_cmd = shutil.which("docker")
            if not docker_cmd:
                raise RuntimeError(
                    "Neither 'infer' nor 'docker' found in PATH. "
                    "Install infer: https://fbinfer.com/docs/getting-started, "
                    "or install Docker and ensure the infer image is available."
                )
            cmd = [
                docker_cmd,
                "run",
                "--rm",
                "-v",
                f"{source_dir}:/src:ro",
                "-v",
                f"{build_dir}:/build",
                "-v",
                f"{output_dir}:/out",
                "-w",
                "/build",
                self.runtime.infer_docker_image,
                "infer",
                "--reactive",
                "--keep-going",
                "--project-root=/src",
                "-o",
                "/out",
            ]
            cmd.extend(self._build_compilation_args(source_dir, compile_commands, local=False))
            cmd.extend(self._build_skip_args(target, source_dir))
            return await asyncio_subprocess(cmd, cwd=build_dir, env=self.runtime.extra_env)

        if not self.runtime.prefer_docker_infer:
            process = await run_local()
            if process and process.returncode != 0:
                process = None  # fall back

        if process is None:
            process = await run_docker()

        if process.returncode != 0:
            raise RuntimeError(f"Infer failed for {target.name}: {process.stderr}")

        report = output_dir / "report.json"
        findings = self._parse_report(report)
        return InferResult(findings=findings, raw_report=report if report.exists() else None)

    def _parse_report(self, report_path: Path) -> list[StaticFinding]:
        if not report_path.exists():
            return []

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        findings: list[StaticFinding] = []
        for issue in payload:
            findings.append(
                StaticFinding(
                    tool="infer",
                    check_id=issue.get("bug_type", "UNKNOWN"),
                    file=issue.get("file", "unknown"),
                    line=int(issue.get("line", 0)),
                    severity=self._map_severity(issue.get("severity")),
                    title=issue.get("qualifier", issue.get("bug_type_hum", "Infer issue")),
                    detail=issue.get("bug_trace", ""),
                    raw_payload=issue,
                )
            )
        return findings

    @staticmethod
    def _map_severity(sev: str | None) -> str:
        normalized = (sev or "LOW").lower()
        if normalized in {"medium", "moderate"}:
            return "medium"
        if normalized in {"high", "major"}:
            return "high"
        if normalized in {"critical", "blocker"}:
            return "critical"
        return "low"

    def _skip_analysis_paths(
        self, target: TargetProjectConfig, source_dir: Path
    ) -> list[str]:
        skips: set[str] = set()

        def add_path(path: Path) -> None:
            skips.add(str(path))

        fuzz_rel = Path(target.fuzz_target)
        fuzz_abs = (source_dir / fuzz_rel).resolve()
        if fuzz_abs.exists():
            add_path(fuzz_abs)

        for pattern in target.harness_globs:
            rel_pattern = PurePosixPath(pattern)
            for match in source_dir.glob(str(rel_pattern)):
                add_path(match.resolve())

        return sorted(skips)

    def _build_compilation_args(
        self, source_dir: Path, compile_commands: Path | None, *, local: bool
    ) -> list[str]:
        if not compile_commands:
            return []
        if local:
            return [f"--compilation-database={compile_commands}"]
        try:
            relative = compile_commands.relative_to(source_dir)
        except ValueError:
            relative = compile_commands
        return [f"--compilation-database=/src/{relative.as_posix()}"]

    def _build_skip_args(self, target: TargetProjectConfig, source_dir: Path) -> list[str]:
        args: list[str] = []
        for skip in self._skip_analysis_paths(target, source_dir):
            args.append(f"--skip-analysis-in-path={skip}")
        return args


async def asyncio_subprocess(cmd: Iterable[str], cwd: Path, env: dict[str, str]):
    """Helper to run blocking subprocess in a background thread."""

    def _run() -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _run)
    if result.returncode != 0:
        result.stderr = result.stderr.strip()  # type: ignore[attr-defined]
    return result

