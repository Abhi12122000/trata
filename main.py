from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .src import MiniCRSOrchestrator, RuntimeConfig, TargetProjectConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mini CRS runner")

    # Target configuration
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

    # Workspace settings
    parser.add_argument("--workspace", type=Path, help="Workspace root override")
    parser.add_argument("--max-parallel", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true")

    # Fuzzing settings
    parser.add_argument(
        "--no-fuzzing",
        action="store_true",
        help="Disable fuzzing (run static analysis only)",
    )
    parser.add_argument(
        "--fuzzing-time",
        type=int,
        default=120,
        help="Total fuzzing time in seconds (default: 120)",
    )
    parser.add_argument(
        "--fuzzing-timeout",
        type=int,
        default=60,
        help="Per-execution timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--fuzzing-workers",
        type=int,
        default=1,
        help="Number of parallel fuzzer workers (default: 1)",
    )

    # LLM settings
    parser.add_argument(
        "--llm-budget-tokens",
        type=int,
        default=32000,
        help="Max tokens for LLM static analysis (default: 32000)",
    )

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
        enable_fuzzing=not args.no_fuzzing,
        fuzzing_max_time=args.fuzzing_time,
        fuzzing_timeout=args.fuzzing_timeout,
        fuzzing_workers=args.fuzzing_workers,
        llm_budget_tokens=args.llm_budget_tokens,
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
    result = await orchestrator.run_single_target(target)

    # Print summary
    print(f"\n{'='*60}")
    print(f"CRS Run Complete: {result.project} ({result.run_id})")
    print(f"{'='*60}")
    print(f"Summary: {result.summary}")
    if result.static_analysis:
        print(f"Static Analysis: {len(result.static_analysis.findings)} findings")
    if result.fuzzing:
        print(f"Fuzzing: {result.fuzzing.crashes_found} crashes, {result.fuzzing.seeds_found} new seeds")
        print(f"Fuzzing duration: {result.fuzzing.duration_seconds:.1f}s")
    print(f"{'='*60}\n")


def main() -> None:
    args = parse_args()
    asyncio.run(_async_main(args))


if __name__ == "__main__":
    main()
