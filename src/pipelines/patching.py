"""
Patching Pipeline - V1 Patcher Implementation

ARCHITECTURE:
1. Creates a WORKING COPY of the source directory (original never modified)
2. Applies patches CUMULATIVELY to the working copy
3. Each successful patch is SAVED to artifacts/patching/patched_files/
4. Builds and tests use the working copy
5. Final working copy contains ALL successfully applied patches

LOGGING:
- All events logged to logs/run.log
- LLM interactions logged to artifacts/patching/llm_interactions.jsonl
- Patch results saved to artifacts/patching/patching_results.json
- Individual patches saved to artifacts/patching/patches/
- Patched files saved to artifacts/patching/patched_files/
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from ..agents.patcher import PatcherAgent, PatcherConfig, PatcherResult
from ..config import RuntimeConfig, TargetProjectConfig
from ..storage.local_store import LocalRunStore
from ..storage.models import (
    BuildArtifacts,
    FuzzCrash,
    RunContext,
    StaticAnalysisBatch,
    StaticFinding,
)
from ..tools.llm_client import LangGraphClient
from ..tools.patch_applier import PatchApplier, PatchResult, ParsedPatch, WorkingCopyManager


@dataclass()
class CrashTestResult:
    """Result of testing a crash against a patched binary."""

    crash_id: str
    harness: str
    still_crashes: bool
    error_message: Optional[str] = None
    signal: Optional[str] = None


@dataclass()
class PatchTestResult:
    """Result of testing a patch against all crashes."""

    finding_id: str
    patch_applied: bool
    build_success: bool
    build_error: Optional[str] = None
    crash_tests: list[CrashTestResult] = field(default_factory=list)
    crashes_fixed: int = 0
    crashes_remaining: int = 0
    patched_file_saved: Optional[str] = None  # Path to saved patched file


@dataclass()
class PatchingBatch:
    """Results of a patching run."""

    project: str
    run_id: str
    findings_processed: int
    patches_generated: int
    patches_applied: int
    patches_tested: int
    patcher_results: list[PatcherResult] = field(default_factory=list)
    test_results: list[PatchTestResult] = field(default_factory=list)
    summary: str = ""
    working_copy_path: Optional[str] = None  # Path to final working copy
    patched_files_path: Optional[str] = None  # Path to saved patched files


class PatchingPipeline:
    """
    Orchestrates the patching process with CUMULATIVE patching.
    
    Flow:
    1. Create working copy of source (original never touched)
    2. For each finding:
       a. Generate patch using LLM
       b. Apply patch to working copy (cumulative)
       c. Rebuild from working copy
       d. Test against crashes
       e. If successful, save patched file
       f. If failed, rollback and try next finding
    3. Final working copy has all successful patches
    """

    def __init__(
        self,
        runtime_config: RuntimeConfig,
        store: Optional[LocalRunStore] = None,
        llm_client: Optional[LangGraphClient] = None,
    ):
        self.runtime = runtime_config
        self.store = store
        self.llm = llm_client or LangGraphClient(runtime_config=runtime_config)

    async def execute(
        self,
        target: TargetProjectConfig,
        build: BuildArtifacts,
        run_ctx: RunContext,
        static_findings: Sequence[StaticFinding],
        crashes: Sequence[FuzzCrash],
    ) -> PatchingBatch:
        """
        Execute the patching pipeline with cumulative patching.

        Args:
            target: Target project config
            build: Build artifacts (original source)
            run_ctx: Run context
            static_findings: Static analysis findings to patch
            crashes: Deduplicated fuzz crashes to test against

        Returns:
            PatchingBatch with all results
        """
        self._log(run_ctx, "=" * 60)
        self._log(run_ctx, "PATCHING PIPELINE STARTED")
        self._log(run_ctx, "=" * 60)
        self._log(run_ctx, f"Findings to process: {len(static_findings)}")
        self._log(run_ctx, f"Crashes to test against: {len(crashes)}")
        self._log(run_ctx, f"Original source: {build.source_dir}")

        batch = PatchingBatch(
            project=target.name,
            run_id=run_ctx.run_id,
            findings_processed=len(static_findings),
            patches_generated=0,
            patches_applied=0,
            patches_tested=0,
        )

        if not static_findings:
            batch.summary = "No findings to patch"
            self._log(run_ctx, batch.summary)
            return batch

        # Step 0: Create working copy
        self._log(run_ctx, "-" * 40)
        self._log(run_ctx, "Step 0: Creating working copy of source...")
        working_copy_mgr = WorkingCopyManager(
            original_source_dir=build.source_dir,
            artifacts_dir=run_ctx.artifacts_dir,
            logger_func=lambda msg: self._log(run_ctx, msg),
        )

        if not working_copy_mgr.initialize():
            batch.summary = "Failed to create working copy"
            self._log(run_ctx, f"ERROR: {batch.summary}")
            return batch

        working_copy_dir = working_copy_mgr.get_working_copy_path()
        batch.working_copy_path = str(working_copy_dir)
        batch.patched_files_path = str(working_copy_mgr.patched_files_dir)
        # Note: Working copy creation is logged by WorkingCopyManager
        self._log(run_ctx, f"Patched files will be saved to: {working_copy_mgr.patched_files_dir}")

        # Step 1+2: Generate, apply, and test patches INCREMENTALLY
        # Each patch sees the working copy with PREVIOUS patches already applied
        self._log(run_ctx, "-" * 40)
        self._log(run_ctx, "INCREMENTAL PATCHING: Generate → Apply → Test (one at a time)")
        self._log(run_ctx, "Each patch sees source WITH previous patches applied")
        self._log(run_ctx, "-" * 40)
        
        patcher_config = PatcherConfig()
        patcher_agent = PatcherAgent(patcher_config, self.llm, self.store)
        
        # Log safety guard limits
        self._log(run_ctx, "Patcher Agent Safety Guards:")
        self._log(run_ctx, f"  - max_patches_per_run: {patcher_config.max_patches_per_run}")
        self._log(run_ctx, f"  - max_llm_calls_per_patch: {patcher_config.max_llm_calls_per_patch}")
        self._log(run_ctx, f"  - max_total_tokens: {patcher_config.max_total_tokens}")
        self._log(run_ctx, f"  - max_retries: {patcher_config.max_retries}")
        
        # Create patch applier for working copy
        applier = PatchApplier(
            working_copy_dir=working_copy_dir,
            logger_func=lambda msg: self._log(run_ctx, msg),
        )

        successful_patches = 0
        for i, finding in enumerate(static_findings):
            self._log(run_ctx, f"\n{'='*40}")
            self._log(run_ctx, f"Finding {i+1}/{len(static_findings)}: {finding.finding_id}")
            self._log(run_ctx, f"{'='*40}")
            
            # Find related crash for this finding
            related_crash = self._find_related_crash(finding, crashes)
            if related_crash:
                self._log(run_ctx, f"Related crash found: {related_crash.crash_id}")
            
            # Step 1a: Generate patch FROM WORKING COPY (with previous patches!)
            self._log(run_ctx, f"Generating patch from: {working_copy_dir}")
            self._log(run_ctx, f"(Source includes {successful_patches} previously applied patches)")
            
            patcher_result = await patcher_agent.generate_patch(
                finding=finding,
                source_root=working_copy_dir,  # USE WORKING COPY for incremental patching!
                run_ctx=run_ctx,
                related_crash=related_crash,
            )
            batch.patcher_results.append(patcher_result)
            
            if not patcher_result.success or not patcher_result.best_patch:
                self._log(run_ctx, f"  [✗] Failed to generate patch: {patcher_result.error_message}")
                continue
            
            batch.patches_generated += 1
            self._log(run_ctx, f"  [✓] Patch generated successfully")
            
            parsed_patch = patcher_result.best_patch
            self._log(run_ctx, f"  File: {parsed_patch.file_path}")
            self._log(run_ctx, f"  Analysis: {parsed_patch.analysis[:80]}...")

            # Step 1b: Apply and test this patch
            test_result = await self._apply_and_test_patch_cumulative(
                target=target,
                build=build,
                run_ctx=run_ctx,
                working_copy_mgr=working_copy_mgr,
                applier=applier,
                patcher_result=patcher_result,
                crashes=crashes,
                patch_index=successful_patches + 1,
            )
            batch.test_results.append(test_result)

            if test_result.patch_applied:
                batch.patches_applied += 1
                successful_patches += 1
            if test_result.build_success:
                batch.patches_tested += 1

        # Cleanup
        working_copy_mgr.cleanup()

        # Build summary using FINAL state of the working copy
        # Since patches are cumulative and failed patches are rolled back,
        # we need to find the last SUCCESSFUL test result to know the current state.
        # Failed patches (build_success=False) are rolled back, so they don't change the state.
        final_fixed = 0
        final_remaining = len(crashes)
        
        # Find the last successful test result - this reflects the actual working copy state
        for result in reversed(batch.test_results):
            if result.build_success and result.crash_tests:
                final_fixed = result.crashes_fixed
                final_remaining = result.crashes_remaining
                break
        
        self._log(run_ctx, "-" * 40)
        self._log(run_ctx, "PATCHING COMPLETE")
        self._log(run_ctx, f"Patches generated: {batch.patches_generated}")
        self._log(run_ctx, f"Patches applied (cumulative): {batch.patches_applied}")
        self._log(run_ctx, f"Patches tested: {batch.patches_tested}")
        self._log(run_ctx, f"Unique crashes fixed (final): {final_fixed}/{len(crashes)}")
        self._log(run_ctx, f"Unique crashes remaining: {final_remaining}")
        
        batch.summary = (
            f"Patching: {batch.patches_generated} generated, "
            f"{batch.patches_applied} applied (cumulative), "
            f"{batch.patches_tested} tested. "
            f"Crashes: {final_fixed}/{len(crashes)} fixed."
        )

        self._log(run_ctx, "=" * 60)
        self._persist_results(run_ctx, batch)
        self._log_final_locations(run_ctx, batch)

        return batch

    async def _apply_and_test_patch_cumulative(
        self,
        target: TargetProjectConfig,
        build: BuildArtifacts,
        run_ctx: RunContext,
        working_copy_mgr: WorkingCopyManager,
        applier: PatchApplier,
        patcher_result: PatcherResult,
        crashes: Sequence[FuzzCrash],
        patch_index: int,
    ) -> PatchTestResult:
        """
        Apply a patch cumulatively and test it.
        
        On success: keeps the patch applied (cumulative)
        On failure: rolls back to before this patch
        """
        finding_id = patcher_result.finding.finding_id
        parsed_patch = patcher_result.best_patch

        test_result = PatchTestResult(
            finding_id=finding_id,
            patch_applied=False,
            build_success=False,
        )

        if not parsed_patch:
            return test_result

        file_path = parsed_patch.file_path

        # Create backup before applying
        backup_path = working_copy_mgr.create_file_backup(file_path)
        if not backup_path:
            test_result.build_error = f"Failed to create backup for {file_path}"
            self._log(run_ctx, f"ERROR: {test_result.build_error}")
            return test_result

        # Validate patch
        validation_errors = applier.validate_patch(file_path, parsed_patch.patch)
        if validation_errors:
            self._log(run_ctx, f"Patch validation warnings: {validation_errors}")

        # Apply patch to working copy
        self._log(run_ctx, f"Applying patch to working copy: {file_path}")
        patch_result = applier.apply_patch(file_path, parsed_patch.patch)

        if not patch_result.success:
            self._log(run_ctx, f"Patch application failed: {patch_result.error_message}")
            test_result.build_error = f"Patch failed: {patch_result.error_message}"
            # Rollback
            working_copy_mgr.restore_from_backup(file_path, backup_path)
            return test_result

        test_result.patch_applied = True
        self._log(run_ctx, f"Patch applied successfully to {file_path}")

        # Rebuild from working copy (IMPORTANT: this ensures patched source is compiled)
        working_copy_dir = working_copy_mgr.get_working_copy_path()
        self._log(run_ctx, f"Rebuilding from working copy: {working_copy_dir}")
        self._log(run_ctx, f"  (Original source is NOT modified)")
        build_success, build_error = await self._rebuild_project(target, working_copy_dir, run_ctx)

        if not build_success:
            self._log(run_ctx, f"Build failed: {build_error}")
            test_result.build_error = build_error
            # Rollback
            self._log(run_ctx, "Rolling back patch due to build failure...")
            working_copy_mgr.restore_from_backup(file_path, backup_path)
            return test_result

        test_result.build_success = True
        self._log(run_ctx, "Build succeeded")

        # Test against crashes (using REBUILT binary from PATCHED source)
        self._log(run_ctx, f"Testing {len(crashes)} crashes against PATCHED binary...")
        
        # Group crashes by harness to use correct fuzzer binary for each
        crashes_by_harness: dict[str, list[FuzzCrash]] = {}
        for crash in crashes:
            harness = crash.harness or "unknown"
            if harness not in crashes_by_harness:
                crashes_by_harness[harness] = []
            crashes_by_harness[harness].append(crash)
        
        self._log(run_ctx, f"  Crashes grouped by harness: {list(crashes_by_harness.keys())}")
        
        for i, crash in enumerate(crashes):
            # Find the correct fuzzer binary for this crash's harness
            fuzzer_binary = self._find_fuzzer_binary_for_harness(
                working_copy_dir, target, crash.harness
            )
            
            if fuzzer_binary:
                if i == 0 or crash.harness != crashes[i-1].harness if i > 0 else True:
                    self._log(run_ctx, f"  Using fuzzer binary for harness '{crash.harness}': {fuzzer_binary}")
                    # Verify binary is in working copy, not original source
                    if "working_copy" in str(fuzzer_binary):
                        self._log(run_ctx, "    ✓ Confirmed: binary is from patched working copy")
            else:
                self._log(run_ctx, f"  WARNING: No fuzzer binary found for harness '{crash.harness}', crash test may fail")
            
            crash_test = await self._test_crash(run_ctx, fuzzer_binary, crash)
            test_result.crash_tests.append(crash_test)
            status = "STILL CRASHES" if crash_test.still_crashes else "FIXED"
            signal = f" ({crash_test.signal})" if crash_test.signal else ""
            self._log(run_ctx, f"  Crash {i+1}/{len(crashes)}: {status}{signal}")
            if crash_test.still_crashes:
                test_result.crashes_remaining += 1
            else:
                test_result.crashes_fixed += 1

        self._log(
            run_ctx,
            f"Crash test summary: {test_result.crashes_fixed} fixed, {test_result.crashes_remaining} remaining",
        )

        # Save patched file (CUMULATIVE - don't rollback on successful build)
        saved_path = working_copy_mgr.save_patched_file(file_path, patch_index, finding_id)
        if saved_path:
            test_result.patched_file_saved = str(saved_path)
            self._log(run_ctx, f"Patched file saved: {saved_path.name}")
        
        # Delete backup (patch is kept)
        if backup_path and backup_path.exists():
            backup_path.unlink()
            self._log(run_ctx, f"Backup deleted (patch committed to working copy)")

        return test_result

    async def _rebuild_project(
        self,
        target: TargetProjectConfig,
        source_dir: Path,
        run_ctx: RunContext,
    ) -> tuple[bool, Optional[str]]:
        """Rebuild the project from the given source directory."""
        # Determine build command in order of priority:
        # 1. Explicitly configured build_script
        # 2. build.sh if it exists
        # 3. make as fallback
        if target.build_script:
            build_script = target.build_script
        elif (source_dir / "build.sh").exists():
            build_script = "./build.sh"
        else:
            build_script = "make"

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                build_script,
                shell=True,
                cwd=source_dir,
                capture_output=True,
                text=True,
                timeout=300,
                env={**os.environ, "FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION": "1"},
            )

            if result.returncode == 0:
                return True, None
            else:
                error = result.stderr[:1000] if result.stderr else result.stdout[:1000]
                return False, error

        except subprocess.TimeoutExpired:
            return False, "Build timed out (300s)"
        except Exception as e:
            return False, str(e)

    def _find_fuzzer_binary(
        self, source_dir: Path, target: Optional[TargetProjectConfig] = None
    ) -> Optional[Path]:
        """
        Find the fuzzer binary in the build directory.
        
        Dynamically derives expected binary names from target.fuzz_targets,
        then falls back to generic patterns.
        """
        build_dir = source_dir / "build"
        if not build_dir.exists():
            build_dir = source_dir

        # First, try deriving binary names from configured fuzz targets
        # This follows the same naming convention as LibFuzzerRunner: fuzzer_{harness_name}
        if target and target.fuzz_targets:
            for harness_path in target.fuzz_targets:
                harness_name = Path(harness_path).stem
                candidates = [
                    f"fuzzer_{harness_name}",  # LibFuzzerRunner convention
                    harness_name,               # Direct name
                ]
                for candidate in candidates:
                    candidate_path = build_dir / candidate
                    if candidate_path.exists() and candidate_path.is_file():
                        return candidate_path

        # Fallback to generic patterns for any project
        generic_patterns = [
            "fuzzer",
            "fuzz_target",
        ]
        
        for candidate in generic_patterns:
            candidate_path = build_dir / candidate
            if candidate_path.exists() and candidate_path.is_file():
                return candidate_path
        
        # Try any executable containing "fuzzer" in the name
        for f in build_dir.glob("*fuzzer*"):
            if f.is_file() and os.access(f, os.X_OK):
                return f
        
        # Try any executable starting with "fuzz"
        for f in build_dir.glob("fuzz*"):
            if f.is_file() and os.access(f, os.X_OK):
                return f
        
        return None

    def _find_fuzzer_binary_for_harness(
        self,
        source_dir: Path,
        target: Optional[TargetProjectConfig],
        harness_name: Optional[str],
    ) -> Optional[Path]:
        """
        Find the fuzzer binary for a specific harness.
        
        Args:
            source_dir: Source directory (working copy)
            target: Target project config
            harness_name: Name of the harness (e.g., "vuln_fuzzer", "packet_fuzzer")
        
        Returns:
            Path to fuzzer binary, or None if not found
        """
        build_dir = source_dir / "build"
        if not build_dir.exists():
            build_dir = source_dir

        # If harness name is provided, try to find matching binary
        if harness_name:
            # IMPORTANT: Try exact match and fuzzer-prefixed variants FIRST
            # to avoid picking up non-fuzzer binaries (e.g., "vuln" standalone vs "vuln_fuzzer")
            candidates = [
                harness_name,                          # Exact match: vuln_fuzzer
                f"fuzzer_{harness_name}",              # LibFuzzerRunner convention: fuzzer_vuln_fuzzer
            ]
            
            for candidate in candidates:
                candidate_path = build_dir / candidate
                if candidate_path.exists() and candidate_path.is_file() and os.access(candidate_path, os.X_OK):
                    return candidate_path
            
            # Also try with common naming patterns but require "fuzzer" in name
            # to avoid matching standalone binaries
            for f in build_dir.glob(f"*{harness_name}*"):
                if f.is_file() and os.access(f, os.X_OK) and "fuzzer" in f.name.lower():
                    return f

        # Fallback to generic search (same as _find_fuzzer_binary)
        return self._find_fuzzer_binary(source_dir, target)

    async def _test_crash(
        self,
        run_ctx: RunContext,
        fuzzer_binary: Optional[Path],
        crash: FuzzCrash,
    ) -> CrashTestResult:
        """Test if a crash still occurs on the patched binary."""
        if not fuzzer_binary or not fuzzer_binary.exists():
            return CrashTestResult(
                crash_id=crash.crash_id,
                harness=crash.harness or "unknown",
                still_crashes=True,
                error_message="Fuzzer binary not found",
            )

        crash_input_path = Path(crash.input_path) if hasattr(crash, "input_path") else None
        if not crash_input_path or not crash_input_path.exists():
            return CrashTestResult(
                crash_id=crash.crash_id,
                harness=crash.harness or "unknown",
                still_crashes=True,
                error_message="Crash input file not found",
            )

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [str(fuzzer_binary), str(crash_input_path), "-runs=1"],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "symbolize=1:abort_on_error=1:detect_leaks=0",
                },
            )

            still_crashes = (
                result.returncode != 0
                or "ERROR:" in result.stderr
                or "SUMMARY:" in result.stderr
            )

            return CrashTestResult(
                crash_id=crash.crash_id,
                harness=crash.harness or "unknown",
                still_crashes=still_crashes,
                signal=self._extract_signal(result.stderr) if still_crashes else None,
            )

        except subprocess.TimeoutExpired:
            return CrashTestResult(
                crash_id=crash.crash_id,
                harness=crash.harness or "unknown",
                still_crashes=True,
                error_message="Test timed out",
            )
        except Exception as e:
            return CrashTestResult(
                crash_id=crash.crash_id,
                harness=crash.harness or "unknown",
                still_crashes=True,
                error_message=str(e),
            )

    def _extract_signal(self, stderr: str) -> Optional[str]:
        """Extract signal type from error output."""
        if "SIGSEGV" in stderr:
            return "SIGSEGV"
        if "heap-use-after-free" in stderr:
            return "HEAP_UAF"
        if "heap-buffer-overflow" in stderr:
            return "HEAP_BOF"
        if "stack-buffer-overflow" in stderr:
            return "STACK_BOF"
        if "double-free" in stderr:
            return "DOUBLE_FREE"
        return None

    def _find_related_crash(
        self,
        finding: StaticFinding,
        crashes: Sequence[FuzzCrash],
    ) -> Optional[FuzzCrash]:
        """Find a crash that might be related to the finding."""
        if not crashes:
            return None
        
        # Try to match by file path in stack trace
        for crash in crashes:
            if crash.stack_trace and finding.file in crash.stack_trace:
                return crash
        
        # Return first crash as fallback (better than nothing)
        return crashes[0] if crashes else None

    def _log(self, run_ctx: RunContext, message: str, level: str = "info") -> None:
        """Log a message with timestamp."""
        timestamp = datetime.now(timezone.utc).isoformat()
        formatted = f"[PatchingPipeline] {message}"
        
        if self.store:
            self.store.log_event(run_ctx, formatted, level=level)
        else:
            print(f"{timestamp} {formatted}")

    def _log_final_locations(self, run_ctx: RunContext, batch: PatchingBatch) -> None:
        """Log where to find all outputs."""
        self._log(run_ctx, "\n" + "=" * 60)
        self._log(run_ctx, "OUTPUT LOCATIONS:")
        self._log(run_ctx, "=" * 60)
        self._log(run_ctx, f"Run logs:           {run_ctx.logs_dir / 'run.log'}")
        self._log(run_ctx, f"Tool calls:         {run_ctx.logs_dir / 'tool_calls.jsonl'}")
        self._log(run_ctx, f"Patching results:   {run_ctx.artifacts_dir / 'patching' / 'patching_results.json'}")
        self._log(run_ctx, f"Generated patches:  {run_ctx.artifacts_dir / 'patching' / 'patches' / ''}")
        self._log(run_ctx, f"LLM interactions:   {run_ctx.artifacts_dir / 'patching' / 'llm_interactions.jsonl'}")
        if batch.working_copy_path:
            self._log(run_ctx, f"Working copy:       {batch.working_copy_path}")
        if batch.patched_files_path:
            self._log(run_ctx, f"Patched files:      {batch.patched_files_path}")
        self._log(run_ctx, "=" * 60)

    def _persist_results(self, run_ctx: RunContext, batch: PatchingBatch) -> None:
        """Persist patching results to JSON."""
        out_file = run_ctx.artifacts_dir / "patching" / "patching_results.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "project": batch.project,
            "run_id": batch.run_id,
            "findings_processed": batch.findings_processed,
            "patches_generated": batch.patches_generated,
            "patches_applied": batch.patches_applied,
            "patches_tested": batch.patches_tested,
            "working_copy_path": batch.working_copy_path,
            "patched_files_path": batch.patched_files_path,
            "patcher_results": [
                {
                    "finding_id": r.finding.finding_id,
                    "vuln_type": r.finding.vuln_type,
                    "file_path": r.finding.file_path,
                    "line": r.finding.line,
                    "success": r.success,
                    "error_message": r.error_message,
                    "patch": r.best_patch.patch if r.best_patch else None,
                    "analysis": r.best_patch.analysis if r.best_patch else None,
                    "fix_strategy": r.best_patch.fix_strategy if r.best_patch else None,
                    "attempts": len(r.attempts),
                }
                for r in batch.patcher_results
            ],
            "test_results": [
                {
                    "finding_id": r.finding_id,
                    "patch_applied": r.patch_applied,
                    "build_success": r.build_success,
                    "build_error": r.build_error,
                    "patched_file_saved": r.patched_file_saved,
                    "crashes_fixed": r.crashes_fixed,
                    "crashes_remaining": r.crashes_remaining,
                    "crash_tests": [
                        {
                            "crash_id": ct.crash_id,
                            "harness": ct.harness,
                            "still_crashes": ct.still_crashes,
                            "error_message": ct.error_message,
                            "signal": ct.signal,
                        }
                        for ct in r.crash_tests
                    ],
                }
                for r in batch.test_results
            ],
            "summary": batch.summary,
        }

        with out_file.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        self._log(run_ctx, f"Saved patching results to patching_results.json")

        # Save raw patches for review
        patches_dir = run_ctx.artifacts_dir / "patching" / "patches"
        patches_dir.mkdir(parents=True, exist_ok=True)

        for i, result in enumerate(batch.patcher_results):
            if result.best_patch:
                safe_file = result.finding.file_path.replace("/", "_")
                patch_file = patches_dir / f"patch_{i+1}_{safe_file}.patch"
                patch_file.write_text(result.best_patch.patch)

        # Save LLM interactions
        llm_log = run_ctx.artifacts_dir / "patching" / "llm_interactions.jsonl"
        with llm_log.open("w", encoding="utf-8") as f:
            for result in batch.patcher_results:
                for attempt in result.attempts:
                    entry = {
                        "timestamp": attempt.timestamp,
                        "finding_id": attempt.finding_id,
                        "llm_response": attempt.llm_response,
                        "parse_error": attempt.parse_error,
                        "parsed_successfully": attempt.parsed_patch is not None,
                    }
                    f.write(json.dumps(entry) + "\n")

        self._log(run_ctx, f"Saved {len(batch.patcher_results)} LLM interactions")
