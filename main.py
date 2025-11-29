from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .src import MiniCRSOrchestrator, RuntimeConfig, TargetProjectConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mini CRS runner")
    parser.add_argument("--name", required=True, help="OSS-Fuzz project name")
    parser.add_argument("--repo", help="Git repository URL (skip if using --local-checkout)")
    parser.add_argument("--local-checkout", type=Path, help="Use an existing local source tree")
    parser.add_argument("--fuzz-target", required=True, help="Primary fuzz target")
    parser.add_argument("--build-script", help="Custom build script (optional)")
    parser.add_argument("--commit", help="Specific commit to analyze")
    parser.add_argument(
        "--harness-glob",
        action="append",
        default=[],
        help="Glob (relative to repo root) identifying harness files to skip; can be repeated",
    )
    parser.add_argument("--workspace", type=Path, help="Workspace root override")
    parser.add_argument("--max-parallel", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.repo and not args.local_checkout:
        parser.error("Either --repo or --local-checkout must be provided")
    return args


async def _async_main(args: argparse.Namespace) -> None:
    runtime = RuntimeConfig(
        workspace_root=args.workspace
        if args.workspace
        else RuntimeConfig().workspace_root,
        max_parallel_jobs=args.max_parallel,
        dry_run=args.dry_run,
    )

    target = TargetProjectConfig(
        name=args.name,
        repo_url=args.repo or "",
        fuzz_target=args.fuzz_target,
        build_script=args.build_script,
        commit=args.commit,
        harness_globs=tuple(args.harness_glob),
        local_checkout=args.local_checkout,
    )

    orchestrator = MiniCRSOrchestrator(runtime)
    await orchestrator.run_single_target(target)


def main() -> None:
    args = parse_args()
    asyncio.run(_async_main(args))


if __name__ == "__main__":
    main()

