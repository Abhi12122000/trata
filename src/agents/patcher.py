"""
V1 Patcher Agent - Generates patches for vulnerabilities using LLM.

This is a simple zero-shot patcher that:
1. Takes a static analysis finding
2. Extracts source code context around the vulnerability
3. Prompts LLM to generate a unified diff patch
4. Returns the patch (application happens separately)
"""

from __future__ import annotations

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
    max_retries: int = 2  # Max LLM call retries per patch
    model: str = "gpt-4o"
    max_tokens_per_patch: int = 4000  # Max tokens per patch generation call
    max_total_tokens: int = 20000  # Total budget for all patches in a run
    max_patches_per_run: int = 10  # Hard limit on patches per CRS run (safety guard)
    max_llm_calls_per_patch: int = 5  # Max LLM interactions per single patch (like Theori's max_iters)
    llm_timeout_seconds: int = 60  # Timeout for each LLM call


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
    
    Safety Guards:
        - max_tokens_per_patch: Max tokens for a single patch generation
        - max_total_tokens: Total budget across all patches
        - max_patches_per_run: Hard limit on number of patches (prevents runaway)
        - max_retries: Max LLM call retries per patch
        - llm_timeout_seconds: Timeout for each LLM call
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
        
        # Token usage tracking
        self._tokens_used = 0
        self._budget_exceeded = False
        
        # Patch count tracking (safety guard)
        self._patches_generated = 0
        self._patches_limit_reached = False
        
        # Per-patch iteration tracking (reset for each patch)
        self._current_patch_llm_calls = 0
        self._total_llm_calls = 0  # Across all patches

    @property
    def tokens_used(self) -> int:
        """Total tokens used so far."""
        return self._tokens_used
    
    @property
    def tokens_remaining(self) -> int:
        """Tokens remaining in budget."""
        return max(0, self.config.max_total_tokens - self._tokens_used)
    
    @property
    def budget_exceeded(self) -> bool:
        """Whether the token budget has been exceeded."""
        return self._budget_exceeded

    @property
    def patches_generated(self) -> int:
        """Number of patches generated so far."""
        return self._patches_generated
    
    @property
    def patches_remaining(self) -> int:
        """Number of patches remaining before limit."""
        return max(0, self.config.max_patches_per_run - self._patches_generated)
    
    @property
    def patches_limit_reached(self) -> bool:
        """Whether the patch generation limit has been reached."""
        return self._patches_limit_reached

    @property
    def current_patch_llm_calls(self) -> int:
        """Number of LLM calls in the current patch generation."""
        return self._current_patch_llm_calls
    
    @property
    def total_llm_calls(self) -> int:
        """Total LLM calls across all patches."""
        return self._total_llm_calls

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

        # Check token budget before proceeding
        if self._budget_exceeded:
            result.error_message = f"Token budget exceeded ({self._tokens_used}/{self.config.max_total_tokens} tokens used)"
            self._log(run_ctx, f"BUDGET EXCEEDED: {result.error_message}", level="warning")
            return result

        # Check patch count limit before proceeding (safety guard)
        if self._patches_limit_reached:
            result.error_message = f"Patch limit reached ({self._patches_generated}/{self.config.max_patches_per_run} patches generated)"
            self._log(run_ctx, f"PATCH LIMIT REACHED: {result.error_message}", level="warning")
            return result

        # Reset per-patch LLM call counter
        self._current_patch_llm_calls = 0

        self._log(run_ctx, f"Generating patch for: {finding.vuln_type} at {finding.file_path}:{finding.line}")
        self._log(run_ctx, f"Token budget: {self._tokens_used}/{self.config.max_total_tokens} used")
        self._log(run_ctx, f"Patch count: {self._patches_generated}/{self.config.max_patches_per_run}")
        self._log(run_ctx, f"Max LLM calls for this patch: {self.config.max_llm_calls_per_patch}")

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
            # Check LLM call limit before making another call
            if self._current_patch_llm_calls >= self.config.max_llm_calls_per_patch:
                result.error_message = (
                    f"LLM call limit reached for this patch "
                    f"({self._current_patch_llm_calls}/{self.config.max_llm_calls_per_patch} calls)"
                )
                self._log(run_ctx, f"LLM CALL LIMIT REACHED: {result.error_message}", level="warning")
                break

            self._log(run_ctx, f"Patch attempt {attempt_num + 1}/{self.config.max_retries + 1} (LLM call {self._current_patch_llm_calls + 1}/{self.config.max_llm_calls_per_patch})")

            try:
                # Increment counters BEFORE calling LLM
                self._current_patch_llm_calls += 1
                self._total_llm_calls += 1
                
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
                    
                    # Increment patch count and check limit
                    self._patches_generated += 1
                    if self._patches_generated >= self.config.max_patches_per_run:
                        self._patches_limit_reached = True
                        self._log(run_ctx, f"PATCH LIMIT will be reached after this patch ({self._patches_generated}/{self.config.max_patches_per_run})", level="warning")
                    
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

        if not result.success and not result.error_message:
            # Only set default error if no specific error was already recorded
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

        # Estimate input tokens (rough: 4 chars per token)
        input_tokens = (len(PATCHER_SYSTEM_PROMPT) + len(user_prompt)) // 4
        
        # Check per-call budget
        if input_tokens > self.config.max_tokens_per_patch:
            self._log(
                run_ctx,
                f"Input exceeds per-patch limit ({input_tokens} > {self.config.max_tokens_per_patch})",
                level="warning",
            )

        # Log the full prompt for debugging/review
        self._log_tool_call(run_ctx, "llm_full_prompt", {
            "model": self.config.model,
            "estimated_input_tokens": input_tokens,
            "system_prompt": PATCHER_SYSTEM_PROMPT,
            "user_prompt": user_prompt,
        })

        response = await self.llm.completion(
            messages=messages,
            model=self.config.model,
            max_tokens=self.config.max_tokens_per_patch,
        )

        # Estimate response tokens and track usage
        output_tokens = len(response) // 4
        total_call_tokens = input_tokens + output_tokens
        self._tokens_used += total_call_tokens
        
        # Check if budget exceeded for future calls
        if self._tokens_used >= self.config.max_total_tokens:
            self._budget_exceeded = True
            self._log(run_ctx, f"TOKEN BUDGET EXHAUSTED: {self._tokens_used}/{self.config.max_total_tokens}", level="warning")

        # Log the full response with token tracking
        self._log_tool_call(run_ctx, "llm_response", {
            "response_length": len(response),
            "estimated_output_tokens": output_tokens,
            "total_call_tokens": total_call_tokens,
            "cumulative_tokens": self._tokens_used,
            "budget_remaining": self.tokens_remaining,
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

