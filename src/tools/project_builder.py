from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import RuntimeConfig, TargetProjectConfig
from ..storage.models import BuildArtifacts, RunContext


@dataclass()
class BuildResult:
    artifacts: BuildArtifacts
    build_log: Path


class ProjectBuilder:
    """Handles checkout + build preparation for an OSS-Fuzz style target."""

    def __init__(self, runtime_config: RuntimeConfig) -> None:
        self.runtime = runtime_config

    async def prepare_target(
        self, target: TargetProjectConfig, run_ctx: RunContext
    ) -> BuildArtifacts:
        source_dir = await self._ensure_checkout(target, run_ctx)
        build_dir = run_ctx.artifacts_dir / "build"
        build_dir.mkdir(parents=True, exist_ok=True)

        build_log = build_dir / "build.log"
        await self._run_build(target, source_dir, build_dir, build_log)

        compile_commands = build_dir / "compile_commands.json"
        if not compile_commands.exists():
            compile_commands = None

        infer_capture = build_dir / "infer-out"
        if not infer_capture.exists():
            infer_capture = None

        return BuildArtifacts(
            source_dir=source_dir,
            build_dir=build_dir,
            compile_commands=compile_commands,
            infer_capture=infer_capture,
            binaries=self._discover_binaries(build_dir),
            metadata={"build_log": str(build_log)},
        )

    async def _ensure_checkout(
        self, target: TargetProjectConfig, run_ctx: RunContext
    ) -> Path:
        if target.local_checkout:
            local_path = target.local_checkout.expanduser().resolve()
            if not local_path.exists():
                raise FileNotFoundError(f"local checkout {local_path} does not exist")
            return local_path

        checkout_dir = run_ctx.artifacts_dir / "src"
        if checkout_dir.exists():
            return checkout_dir

        checkout_dir.mkdir(parents=True, exist_ok=True)
        await self._run_command(
            ["git", "clone", target.repo_url, str(checkout_dir)],
            cwd=run_ctx.artifacts_dir,
        )
        if target.commit:
            await self._run_command(
                ["git", "checkout", target.commit], cwd=checkout_dir
            )
        elif not target.repo_url:
            raise RuntimeError("repo_url must be provided when no --local-checkout is set")
        return checkout_dir

    async def _run_build(
        self,
        target: TargetProjectConfig,
        source_dir: Path,
        build_dir: Path,
        log_path: Path,
    ) -> None:
        if target.build_script is not None:
            cmd = ["bash", "-c", target.build_script]
        elif target.build_system == "oss-fuzz":
            cmd = [
                "python3",
                "infra/helper.py",
                "build_fuzzers",
                target.name,
            ]
        else:
            cmd = ["cmake", "--build", str(build_dir)]

        result = await self._run_command(cmd, cwd=source_dir)
        log_path.write_text(
            f"$ {' '.join(cmd)}\n{result.stdout}\n{result.stderr}", encoding="utf-8"
        )

    async def _run_command(self, cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            ),
        )

    def _discover_binaries(self, build_dir: Path) -> list[Path]:
        binaries: list[Path] = []
        for path in build_dir.rglob("*"):
            if path.is_file() and path.stat().st_mode & 0o111:
                binaries.append(path)
        return binaries

