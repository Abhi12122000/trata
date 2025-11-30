"""
LibFuzzer Runner for the mini CRS.

Handles building and running libFuzzer-instrumented binaries.
Designed to run locally first, with Docker support planned for later.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from ..config import RuntimeConfig, TargetProjectConfig
from ..storage.models import BuildArtifacts, FuzzCrash, FuzzingBatch, FuzzingConfig, RunContext
from .corpus_manager import CorpusManager


@dataclass()
class LibFuzzerResult:
    """Result of a single libFuzzer run."""

    returncode: int
    duration_seconds: float
    new_seeds: list[str]
    new_crashes: list[FuzzCrash]
    stdout: str
    stderr: str


class LibFuzzerRunner:
    """
    Runs libFuzzer on compiled harnesses.

    Responsibilities:
        - Build fuzzer binary with sanitizers (if not already built)
        - Execute libFuzzer with configurable timeout
        - Collect new seeds and crashes
        - Parse crash files for deduplication tokens
    """

    def __init__(self, runtime_config: RuntimeConfig) -> None:
        self.runtime = runtime_config

    async def build_fuzzer(
        self,
        target: TargetProjectConfig,
        build: BuildArtifacts,
        run_ctx: RunContext,
        harness_override: str | None = None,
    ) -> Path | None:
        """
        Build the fuzzer binary with sanitizers.

        Args:
            target: Target project configuration
            build: Build artifacts
            run_ctx: Run context for logging
            harness_override: Optional path to a specific harness (for multi-harness)

        Returns path to fuzzer binary, or None if build fails.
        """
        # Determine which harness to use
        harness_path = harness_override or target.fuzz_target
        harness_name = Path(harness_path).stem
        
        # Check if fuzzer binary already exists for this harness
        fuzzer_binary = build.build_dir / f"fuzzer_{harness_name}"
        if fuzzer_binary.exists():
            self._log(run_ctx, f"Fuzzer binary already exists: {fuzzer_binary}")
            return fuzzer_binary

        # Find clang with libFuzzer support
        # Priority: Homebrew LLVM > System clang
        clang = self._find_clang_with_fuzzer(run_ctx)
        if not clang:
            return None

        # Determine source files
        source_dir = build.source_dir
        fuzz_target = source_dir / harness_path

        if not fuzz_target.exists():
            self._log(run_ctx, f"Fuzz target not found: {fuzz_target}")
            return None

        # Find main source files (assume it's in src/ directory)
        # Exclude main.c and any fuzzer files
        main_sources = list(source_dir.glob("src/*.c"))
        if not main_sources:
            main_sources = list(source_dir.glob("*.c"))
        
        # Filter out main.c (contains standalone main()) and fuzzer files
        main_sources = [
            s for s in main_sources 
            if s.name.lower() not in ("main.c", "main.cpp") 
            and "fuzzer" not in s.name.lower()
        ]

        if not main_sources:
            self._log(run_ctx, "No source files found to compile with fuzzer")
            return None
        
        # For Homebrew LLVM, we need to link against its libc++ to avoid ABI mismatches
        # with the fuzzer runtime library
        extra_flags = self._get_llvm_lib_flags(clang)
        
        cmd = [
            clang,
            "-fsanitize=fuzzer,address",
            "-g",
            "-O1",
            "-fno-omit-frame-pointer",
            # Define FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION to exclude standalone main()
            # This is a standard libFuzzer convention
            "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            *extra_flags,
            *[str(s) for s in main_sources],
            str(fuzz_target),
            "-o",
            str(fuzzer_binary),
        ]

        self._log(run_ctx, f"Building fuzzer: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                cwd=source_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                self._log(run_ctx, f"Fuzzer build failed:\n{result.stderr}")
                return None

            if not fuzzer_binary.exists():
                self._log(run_ctx, "Fuzzer binary not created")
                return None

            self._log(run_ctx, f"Fuzzer built successfully: {fuzzer_binary}")
            return fuzzer_binary

        except subprocess.TimeoutExpired:
            self._log(run_ctx, "Fuzzer build timed out")
            return None
        except Exception as e:
            self._log(run_ctx, f"Error building fuzzer: {e}")
            return None

    async def run(
        self,
        fuzzer_binary: Path,
        corpus_manager: CorpusManager,
        config: FuzzingConfig,
        run_ctx: RunContext,
    ) -> LibFuzzerResult:
        """
        Execute libFuzzer and collect results.

        Args:
            fuzzer_binary: Path to compiled fuzzer
            corpus_manager: Manages seeds and crashes
            config: Fuzzing configuration
            run_ctx: Run context for logging

        Returns:
            LibFuzzerResult with seeds, crashes, and stats
        """
        # Create working directories
        work_dir = run_ctx.artifacts_dir / "fuzzing"
        work_dir.mkdir(parents=True, exist_ok=True)

        corpus_work_dir = work_dir / "corpus"
        crashes_work_dir = work_dir / "crashes"
        corpus_work_dir.mkdir(exist_ok=True)
        crashes_work_dir.mkdir(exist_ok=True)

        # Copy existing seeds to working corpus
        corpus_manager.copy_seeds_to(corpus_work_dir)
        initial_seeds = len(list(corpus_work_dir.iterdir()))

        # Build libFuzzer command
        cmd = [
            str(fuzzer_binary),
            str(corpus_work_dir),
            f"-max_total_time={config.max_total_time}",
            f"-timeout={config.timeout_seconds}",
            f"-artifact_prefix={crashes_work_dir}/",
            f"-jobs={config.workers}",
            f"-workers={config.workers}",
            "-fork=1",  # Fork mode for crash recovery
            "-ignore_crashes=1",  # Continue after crashes
            f"-detect_leaks={'1' if config.detect_leaks else '0'}",
            "-print_final_stats=1",
        ]

        self._log(run_ctx, f"Running fuzzer: {' '.join(cmd)}")

        start_time = time.perf_counter()
        new_crashes: list[FuzzCrash] = []

        try:
            # Run libFuzzer
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
                env={
                    **os.environ,
                    # Sanitizer options for better crash reports
                    "ASAN_OPTIONS": "symbolize=1:abort_on_error=1:detect_leaks=0",
                    "UBSAN_OPTIONS": "print_stacktrace=1",
                },
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=config.max_total_time + 60,  # Grace period
            )

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            returncode = process.returncode or 0

        except asyncio.TimeoutError:
            self._log(run_ctx, "Fuzzer timed out")
            process.kill()
            stdout = ""
            stderr = "Fuzzer timed out"
            returncode = -1

        except Exception as e:
            self._log(run_ctx, f"Error running fuzzer: {e}")
            stdout = ""
            stderr = str(e)
            returncode = -1

        duration = time.perf_counter() - start_time

        # Sync new seeds from fuzzer
        new_seed_ids = corpus_manager.sync_seeds_from(corpus_work_dir)
        self._log(run_ctx, f"Found {len(new_seed_ids)} new seeds")

        # Collect crashes
        for crash_file in crashes_work_dir.iterdir():
            if crash_file.is_file() and not crash_file.name.startswith("."):
                crash = await self._process_crash(
                    crash_file,
                    corpus_manager,
                    stderr,
                )
                if crash:
                    new_crashes.append(crash)

        self._log(run_ctx, f"Found {len(new_crashes)} crashes")

        # Write fuzzer output to log
        log_file = work_dir / "fuzzer.log"
        log_file.write_text(f"=== STDOUT ===\n{stdout}\n\n=== STDERR ===\n{stderr}")

        return LibFuzzerResult(
            returncode=returncode,
            duration_seconds=duration,
            new_seeds=new_seed_ids,
            new_crashes=new_crashes,
            stdout=stdout,
            stderr=stderr,
        )

    async def _process_crash(
        self,
        crash_file: Path,
        corpus_manager: CorpusManager,
        stderr: str,
    ) -> FuzzCrash | None:
        """Process a crash file and add to corpus manager."""
        try:
            crash_data = crash_file.read_bytes()
            crash_name = crash_file.name

            # Extract dedup token from crash filename or stderr
            # libFuzzer names crashes like: crash-<hash> or oom-<hash> or timeout-<hash>
            dedup_token = self._extract_dedup_token(crash_name, stderr)
            signal = self._extract_signal(crash_name)

            # Extract stack trace from stderr if available
            stack_trace = self._extract_stack_trace(stderr, crash_name)

            return await corpus_manager.add_crash(
                data=crash_data,
                dedup_token=dedup_token,
                harness=corpus_manager.harness_name,
                stack_trace=stack_trace,
                signal=signal,
            )

        except Exception:
            return None

    @staticmethod
    def _extract_dedup_token(crash_name: str, stderr: str) -> str:
        """Extract deduplication token from crash name or stderr."""
        # Try to get from crash filename
        if "-" in crash_name:
            return crash_name.split("-", 1)[1][:16]

        # Try to extract from ASAN output
        # Look for patterns like "==12345==ERROR: AddressSanitizer: ..."
        match = re.search(r"ERROR: \w+Sanitizer: (\w+)", stderr)
        if match:
            return match.group(1)

        return crash_name[:16] if crash_name else "unknown"

    @staticmethod
    def _extract_signal(crash_name: str) -> str:
        """Extract signal type from crash filename."""
        crash_name_lower = crash_name.lower()
        if crash_name_lower.startswith("crash"):
            return "SIGSEGV"
        if crash_name_lower.startswith("oom"):
            return "OOM"
        if crash_name_lower.startswith("timeout"):
            return "TIMEOUT"
        if crash_name_lower.startswith("leak"):
            return "LEAK"
        return ""

    @staticmethod
    def _extract_stack_trace(stderr: str, crash_name: str) -> str:
        """Extract stack trace from stderr related to a crash."""
        # Look for ASAN/UBSAN stack traces
        lines = stderr.split("\n")
        in_trace = False
        trace_lines: list[str] = []

        for line in lines:
            if "ERROR:" in line and "Sanitizer" in line:
                in_trace = True
                trace_lines = [line]
            elif in_trace:
                if line.strip().startswith("#") or line.strip().startswith("=="):
                    trace_lines.append(line)
                elif line.strip() == "" and len(trace_lines) > 5:
                    break

        return "\n".join(trace_lines[:50])  # Limit stack trace length

    def _find_clang_with_fuzzer(self, run_ctx: RunContext) -> str | None:
        """Find a clang binary that supports -fsanitize=fuzzer."""
        # Candidates in order of preference
        candidates = [
            "/opt/homebrew/opt/llvm/bin/clang",  # Homebrew on Apple Silicon
            "/usr/local/opt/llvm/bin/clang",  # Homebrew on Intel Mac
            shutil.which("clang"),  # System clang
        ]

        for clang in candidates:
            if not clang or not Path(clang).exists():
                continue

            try:
                # Test compile only (not link) to check fuzzer support
                result = subprocess.run(
                    [clang, "-fsanitize=fuzzer", "-x", "c", "-c", "/dev/null", "-o", "/dev/null"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    self._log(run_ctx, f"Found clang with fuzzer support: {clang}")
                    return clang
            except Exception:
                continue

        self._log(
            run_ctx,
            "No clang with -fsanitize=fuzzer found. "
            "On macOS, install LLVM: brew install llvm && "
            "export PATH=\"/opt/homebrew/opt/llvm/bin:$PATH\"",
        )
        return None

    def _get_llvm_lib_flags(self, clang: str) -> list[str]:
        """
        Get extra linker flags needed for Homebrew LLVM.
        
        Homebrew LLVM's fuzzer runtime is built against its own libc++,
        so we need to link against that to avoid ABI mismatches.
        """
        # Check if this is Homebrew LLVM
        if "/opt/homebrew/opt/llvm" in clang:
            llvm_lib = "/opt/homebrew/opt/llvm/lib/c++"
            if Path(llvm_lib).exists():
                return [f"-L{llvm_lib}", "-Wl,-rpath," + llvm_lib]
        elif "/usr/local/opt/llvm" in clang:
            llvm_lib = "/usr/local/opt/llvm/lib/c++"
            if Path(llvm_lib).exists():
                return [f"-L{llvm_lib}", "-Wl,-rpath," + llvm_lib]
        
        return []

    def _log(self, run_ctx: RunContext, message: str) -> None:
        """Log a message to the run log."""
        log_file = run_ctx.logs_dir / "fuzzing.log"
        timestamp = datetime.now(timezone.utc).isoformat()
        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

