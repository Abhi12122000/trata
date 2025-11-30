"""
V1 Patcher Agent - Generates patches for vulnerabilities using LLM.

This is a simple zero-shot patcher that:
1. Takes a static analysis finding
2. Extracts source code context around the vulnerability
3. Prompts LLM to generate a unified diff patch
4. Returns the patch (application happens separately)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from ..prompts.patcher import (
    PATCHER_SYSTEM_PROMPT,
    PATCHER_USER_PROMPT_TEMPLATE,
    PATCHER_USER_PROMPT_WITH_FUZZ_CRASH,
)
from ..storage.models import RunContext, StaticFinding, FuzzCrash
from ..tools.llm_client import LangGraphClient
from ..tools.patch_applier import ParsedPatch, PatchParser


@dataclass()
class PatcherConfig:
    """Configuration for the patcher agent."""

    context_lines: int = 50  # Lines before/after vulnerability to show
    max_retries: int = 2
    model: str = "gpt-4o"


@dataclass()
class PatchAttempt:
    """Record of a single patch attempt."""

    finding_id: str
    timestamp: str
    llm_response: str
    parsed_patch: Optional[ParsedPatch]
    parse_error: Optional[str] = None


@dataclass()
class PatcherResult:
    """Result of the patcher agent."""

    finding: StaticFinding
    attempts: list[PatchAttempt] = field(default_factory=list)
    best_patch: Optional[ParsedPatch] = None
    success: bool = False
    error_message: Optional[str] = None


class PatcherAgent:
    """
    V1 Patcher Agent - Generates patches for vulnerabilities.

    Usage:
        agent = PatcherAgent(config, llm_client, store)
        result = await agent.generate_patch(finding, source_root, run_ctx)
    """

    def __init__(
        self,
        config: PatcherConfig,
        llm_client: LangGraphClient,
        store: Optional["LocalRunStore"] = None,
    ):
        self.config = config
        self.llm = llm_client
        self.store = store
        self.parser = PatchParser()

    async def generate_patch(
        self,
        finding: StaticFinding,
        source_root: Path,
        run_ctx: RunContext,
        related_crash: Optional[FuzzCrash] = None,
    ) -> PatcherResult:
        """
        Generate a patch for a static analysis finding.

        Args:
            finding: The vulnerability to patch
            source_root: Root directory of the source code
            run_ctx: Run context for logging
            related_crash: Optional related fuzz crash for additional context

        Returns:
            PatcherResult with the generated patch (if successful)
        """
        result = PatcherResult(finding=finding)

        self._log(run_ctx, f"Generating patch for: {finding.vuln_type} at {finding.file_path}:{finding.line}")

        # Extract source context
        source_context = self._extract_source_context(
            source_root, finding.file_path, finding.line
        )

        if not source_context:
            result.error_message = f"Could not read source file: {finding.file_path}"
            self._log(run_ctx, result.error_message, level="error")
            return result

        # Build prompt
        prompt = self._build_prompt(finding, source_context, related_crash)

        # Try to generate patch
        for attempt_num in range(self.config.max_retries + 1):
            self._log(run_ctx, f"Patch attempt {attempt_num + 1}/{self.config.max_retries + 1}")

            try:
                llm_response = await self._call_llm(prompt, run_ctx)
                attempt = PatchAttempt(
                    finding_id=finding.finding_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    llm_response=llm_response,
                    parsed_patch=None,
                )

                # Try to parse the response
                parsed = self.parser.parse_yaml_response(llm_response)
                if parsed:
                    attempt.parsed_patch = parsed
                    result.attempts.append(attempt)
                    result.best_patch = parsed
                    result.success = True
                    self._log(run_ctx, f"Successfully parsed patch for {parsed.file_path}")
                    self._log_patch(run_ctx, parsed)
                    break
                else:
                    attempt.parse_error = "Failed to parse YAML response"
                    result.attempts.append(attempt)
                    self._log(run_ctx, "Failed to parse LLM response as YAML patch", level="warning")

            except Exception as e:
                attempt = PatchAttempt(
                    finding_id=finding.finding_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    llm_response="",
                    parsed_patch=None,
                    parse_error=str(e),
                )
                result.attempts.append(attempt)
                self._log(run_ctx, f"LLM call failed: {e}", level="error")

        if not result.success:
            result.error_message = "Failed to generate valid patch after all retries"
            self._log(run_ctx, result.error_message, level="error")

        return result

    def _extract_source_context(
        self,
        source_root: Path,
        file_path: str,
        center_line: int,
    ) -> Optional[str]:
        """Extract source code context around the vulnerability."""
        target_file = source_root / file_path

        if not target_file.exists():
            return None

        try:
            lines = target_file.read_text().splitlines()
            total_lines = len(lines)

            # Calculate range
            start = max(0, center_line - self.config.context_lines - 1)
            end = min(total_lines, center_line + self.config.context_lines)

            # Build context with line numbers
            context_lines = []
            for i in range(start, end):
                line_num = i + 1
                marker = ">>> " if line_num == center_line else "    "
                context_lines.append(f"{line_num:4d}{marker}{lines[i]}")

            return "\n".join(context_lines)

        except Exception:
            return None

    def _build_prompt(
        self,
        finding: StaticFinding,
        source_context: str,
        related_crash: Optional[FuzzCrash] = None,
    ) -> str:
        """Build the user prompt for the LLM."""
        # Determine language from file extension
        ext = Path(finding.file_path).suffix.lower()
        language = {
            ".c": "c",
            ".h": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".hpp": "cpp",
            ".java": "java",
            ".py": "python",
        }.get(ext, "c")

        function_context = ""
        if finding.function_name:
            function_context = f"\n**Function:** {finding.function_name}"

        if related_crash:
            return PATCHER_USER_PROMPT_WITH_FUZZ_CRASH.format(
                vuln_type=finding.vuln_type,
                severity=finding.severity,
                file_path=finding.file_path,
                line_number=finding.line,
                description=finding.description,
                function_context=function_context,
                stack_trace=related_crash.stack_trace or "N/A",
                language=language,
                source_context=source_context,
            )
        else:
            return PATCHER_USER_PROMPT_TEMPLATE.format(
                vuln_type=finding.vuln_type,
                severity=finding.severity,
                file_path=finding.file_path,
                line_number=finding.line,
                description=finding.description,
                function_context=function_context,
                language=language,
                source_context=source_context,
            )

    async def _call_llm(self, user_prompt: str, run_ctx: RunContext) -> str:
        """Call the LLM with the patcher prompt."""
        messages = [
            {"role": "system", "content": PATCHER_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        # Log the full prompt for debugging/review
        self._log_tool_call(run_ctx, "llm_full_prompt", {
            "model": self.config.model,
            "system_prompt": PATCHER_SYSTEM_PROMPT,
            "user_prompt": user_prompt,
        })

        response = await self.llm.completion(
            messages=messages,
            model=self.config.model,
        )

        # Log the full response
        self._log_tool_call(run_ctx, "llm_response", {
            "response_length": len(response),
            "response": response,
        })

        return response

    def _log(self, run_ctx: RunContext, message: str, level: str = "info") -> None:
        """Log a message."""
        if self.store:
            self.store.log_event(run_ctx, f"[PatcherAgent] {message}", level=level)
        else:
            print(f"[PatcherAgent] {message}")

    def _log_tool_call(self, run_ctx: RunContext, tool_name: str, args: dict) -> None:
        """Log a tool call."""
        if self.store:
            self.store.log_tool_call(
                run_ctx,
                tool=f"patcher.{tool_name}",
                action="invoke",
                detail=args,
            )

    def _log_patch(self, run_ctx: RunContext, patch: ParsedPatch) -> None:
        """Log the generated patch."""
        if self.store:
            patch_log = {
                "analysis": patch.analysis,
                "fix_strategy": patch.fix_strategy,
                "file_path": patch.file_path,
                "patch": patch.patch,
            }
            self.store.log_tool_call(
                run_ctx,
                tool="patcher.generated_patch",
                action="output",
                detail=patch_log,
            )


async def generate_patches_for_findings(
    findings: Sequence[StaticFinding],
    source_root: Path,
    run_ctx: RunContext,
    config: Optional[PatcherConfig] = None,
    llm_client: Optional[LangGraphClient] = None,
    store: Optional["LocalRunStore"] = None,
    crashes: Optional[Sequence[FuzzCrash]] = None,
) -> list[PatcherResult]:
    """
    Generate patches for multiple static analysis findings.

    Args:
        findings: List of findings to patch
        source_root: Root directory of source code
        run_ctx: Run context for logging
        config: Patcher configuration
        llm_client: LLM client
        store: Local run store for logging
        crashes: Optional list of related crashes

    Returns:
        List of PatcherResults
    """
    config = config or PatcherConfig()
    llm_client = llm_client or LangGraphClient()
    agent = PatcherAgent(config, llm_client, store)

    results = []

    # Build crash lookup by file/line for matching
    crash_lookup: dict[tuple[str, int], FuzzCrash] = {}
    if crashes:
        for crash in crashes:
            if crash.stack_trace:
                # Try to extract file:line from stack trace
                import re
                matches = re.findall(r"(\w+\.\w+):(\d+)", crash.stack_trace)
                for file_name, line_str in matches:
                    crash_lookup[(file_name, int(line_str))] = crash

    for finding in findings:
        # Try to find related crash
        related_crash = crash_lookup.get(
            (Path(finding.file_path).name, finding.line)
        )

        result = await agent.generate_patch(
            finding=finding,
            source_root=source_root,
            run_ctx=run_ctx,
            related_crash=related_crash,
        )
        results.append(result)

    return results

