from __future__ import annotations

import asyncio
import fnmatch
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from ..config import RuntimeConfig, TargetProjectConfig
from ..prompts.static_analysis import build_static_analysis_prompt
from ..storage import LocalRunStore
from ..storage.models import BuildArtifacts, RunContext, StaticFinding

try:
    from langchain_openai import ChatOpenAI
except ImportError:  # pragma: no cover - optional dependency
    ChatOpenAI = None  # type: ignore


class LangGraphClient:
    """
    Encapsulates the LangGraph-inspired workflow used for static analysis.

    The implementation keeps an explicit record of every pseudo-tool call:
    - `source_locator` chooses which files to inspect.
    - `source_reader` streams code snippets to the agent.
    - `llm_static_analysis` sends structured prompts to the LLM.
    The resulting JSONL log lets us replay the entire reasoning process.
    """

    def __init__(self, runtime_config: RuntimeConfig, max_files: int | None = None, max_lines: int = 200) -> None:
        self.runtime = runtime_config
        self.max_files = max_files
        self.max_lines = max_lines
        self._tokens_used = 0
        self._max_tokens = runtime_config.llm_budget_tokens
        self._max_retries = 3
        self._retry_count = 0
        
        # Static analysis limits
        self._llm_calls_made = 0
        self._max_llm_calls = runtime_config.static_max_llm_calls
        self._max_findings_per_file = runtime_config.static_max_findings_per_file
        self._max_total_findings = runtime_config.static_max_total_findings
        self._total_findings = 0
        
        # Try to initialize LLM, fall back to offline mode if no API key
        try:
            self._llm = ChatOpenAI(model=runtime_config.langgraph_model) if ChatOpenAI else None
        except Exception:
            # No API key or invalid config - run in offline mode
            self._llm = None

    async def run_static_review(
        self,
        target: TargetProjectConfig,
        build: BuildArtifacts,
        run_ctx: RunContext,
        store: LocalRunStore | None = None,
    ) -> tuple[str, Sequence[StaticFinding]]:
        # Log start of static analysis
        self._log_event(run_ctx, store, "LLM Static Analysis starting")
        self._log_event(
            run_ctx, store, 
            f"LLM limits: max_calls={self._max_llm_calls}, "
            f"max_findings_per_file={self._max_findings_per_file}, "
            f"max_total_findings={self._max_total_findings}, "
            f"token_budget={self._max_tokens}"
        )
        
        candidate_files, skipped = self._select_candidate_files(target, build)
        
        self._log_event(
            run_ctx, store,
            f"File selection: {len(candidate_files)} files to analyze, {len(skipped)} skipped"
        )
        
        self._log_tool(
            run_ctx,
            store,
            "source_locator",
            "selected",
            {
                "files": [str(p) for p in candidate_files],
                "skipped": skipped,
                "reason": (
                    "C/C++ sources prioritized; fuzz targets and harnesses excluded"
                ),
            },
        )

        summaries: list[str] = []
        findings: list[StaticFinding] = []

        for idx, file_path in enumerate(candidate_files):
            # Check LLM call limit
            if self._llm_calls_made >= self._max_llm_calls:
                self._log_event(
                    run_ctx, store, 
                    f"LLM call limit reached ({self._max_llm_calls}). Stopping analysis."
                )
                break
            
            # Check total findings limit
            if self._total_findings >= self._max_total_findings:
                self._log_event(
                    run_ctx, store,
                    f"Total findings limit reached ({self._max_total_findings}). Stopping analysis."
                )
                break
            
            snippet = self._read_snippet(file_path)
            self._log_tool(run_ctx, store, "source_reader", "snippet_extracted", {
                "file": str(file_path),
                "lines_returned": snippet.count("\n") + 1,
                "max_lines": self.max_lines,
            })

            try:
                relative_file = file_path.relative_to(build.source_dir)
            except ValueError:
                relative_file = file_path

            self._log_event(
                run_ctx, store,
                f"Analyzing file {idx + 1}/{len(candidate_files)}: {relative_file}"
            )

            prompt = build_static_analysis_prompt(
                project=target.name,
                fuzz_target=", ".join(target.fuzz_targets) if target.fuzz_targets else "N/A",
                file_path=str(relative_file),
                code_snippet=snippet,
                max_findings=self._max_findings_per_file,
                max_lines=self.max_lines,
            )

            # Check token budget before invoking
            prompt_tokens_est = len(prompt.split()) * 1.3  # rough estimate
            if self._tokens_used + prompt_tokens_est > self._max_tokens:
                self._log_event(
                    run_ctx, store,
                    f"Token budget exhausted ({int(self._tokens_used)}/{self._max_tokens}). Using offline fallback."
                )
                self._log_tool(run_ctx, store, "llm_static_analysis", "budget_exceeded", {
                    "file": str(file_path),
                    "tokens_used": int(self._tokens_used),
                    "budget": self._max_tokens,
                    "skipped": True,
                })
                summary, snippet_findings = self._offline_summary(
                    file_path, snippet, "[budget exhausted]"
                )
                summaries.append(summary)
                findings.extend(snippet_findings)
                break  # Stop processing more files
            
            try:
                response_text = await self._invoke_llm(prompt)
                self._llm_calls_made += 1
                self._tokens_used += int(prompt_tokens_est * 2)  # rough: prompt + response
                self._retry_count = 0  # reset on success
            except Exception as e:
                self._retry_count += 1
                if self._retry_count >= self._max_retries:
                    self._log_event(
                        run_ctx, store,
                        f"Max retries exceeded for {relative_file}: {e}"
                    )
                    self._log_tool(run_ctx, store, "llm_static_analysis", "max_retries_exceeded", {
                        "file": str(file_path),
                        "error": str(e),
                        "retries": self._retry_count,
                    })
                    summary, snippet_findings = self._offline_summary(
                        file_path, snippet, str(e)
                    )
                    summaries.append(summary)
                    findings.extend(snippet_findings)
                    break
                # Continue to next file on retry
                continue
            
            self._log_tool(run_ctx, store, "llm_static_analysis", "invoke", {
                "file": str(file_path),
                "prompt_tokens_estimate": int(prompt_tokens_est),
                "tokens_used_total": int(self._tokens_used),
                "llm_calls_made": self._llm_calls_made,
                "response": response_text[:8000],  # keep logs bounded
            })

            summary, snippet_findings = self._parse_llm_response(
                response_text,
                default_file=str(relative_file),
            )
            
            # Track findings and log
            self._total_findings += len(snippet_findings)
            self._log_event(
                run_ctx, store,
                f"  Found {len(snippet_findings)} findings in {relative_file} "
                f"(total: {self._total_findings}, LLM calls: {self._llm_calls_made})"
            )
            summaries.append(summary)
            findings.extend(snippet_findings)

        # Final summary
        self._log_event(
            run_ctx, store,
            f"LLM Static Analysis complete: {len(findings)} findings from {self._llm_calls_made} LLM calls"
        )
        
        combined_summary = self._compose_summary(target, summaries, findings)
        (run_ctx.logs_dir / "llm_summary.json").write_text(
            json.dumps(
                {
                    "files": [str(p.relative_to(build.source_dir)) for p in candidate_files],
                    "summary": combined_summary,
                    "findings": [f.__dict__ for f in findings],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return combined_summary, findings

    def _select_candidate_files(
        self, target: TargetProjectConfig, build: BuildArtifacts
    ) -> tuple[list[Path], list[str]]:
        selected: list[Path] = []
        skipped: list[str] = []
        harness_patterns = self._harness_patterns(target)

        build_dir_resolved = None
        if build.build_dir:
            try:
                build_dir_resolved = build.build_dir.resolve(strict=False)
            except FileNotFoundError:
                build_dir_resolved = build.build_dir

        def _is_under(child: Path, parent: Path) -> bool:
            if hasattr(child, "is_relative_to"):
                try:
                    return child.is_relative_to(parent)
                except ValueError:
                    return False
            try:
                child.relative_to(parent)
                return True
            except ValueError:
                return False

        def should_skip(path: Path) -> bool:
            rel = self._relative_posix(path, build.source_dir)
            if build_dir_resolved and _is_under(path, build_dir_resolved):
                skipped.append(f"{rel}:build_artifact")
                return True
            if rel.startswith("objs/"):
                skipped.append(f"{rel}:build_artifact")
                return True
            if not self._is_c_cpp(path):
                skipped.append(f"{rel}:non-cpp")
                return True
            # Skip all fuzz targets
            for fuzz_tgt in target.fuzz_targets:
                if rel == fuzz_tgt or rel.startswith(f"{fuzz_tgt}/"):
                    skipped.append(f"{rel}:fuzz_target")
                    return True
            for pattern in harness_patterns:
                if fnmatch.fnmatch(rel, pattern):
                    skipped.append(f"{rel}:harness")
                    return True
            return False

        for path in build.source_dir.rglob("*"):
            if not path.is_file():
                continue
            if should_skip(path):
                continue
            if self.max_files is not None and len(selected) >= self.max_files:
                break
            selected.append(path)
        return selected[: self.max_files], skipped

    def _read_snippet(self, file_path: Path) -> str:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except FileNotFoundError:
            return ""
        snippet = "\n".join(lines[: self.max_lines])
        return snippet

    async def _invoke_llm(self, prompt: str) -> str:
        if not self._llm:
            return self._offline_response(prompt)
        loop = asyncio.get_running_loop()
        completion = await loop.run_in_executor(None, lambda: self._llm.invoke(prompt))
        return completion.content if hasattr(completion, "content") else str(completion)

    def _offline_response(self, prompt: str) -> str:
        # Simple heuristic fallback that mimics JSON output with proper check_ids
        danger_patterns = {
            "strcpy": ("BUFFER_OVERRUN", "high", "Unbounded string copy via strcpy"),
            "memcpy": ("BUFFER_OVERRUN", "medium", "Potential buffer overflow via memcpy"),
            "sprintf": ("BUFFER_OVERRUN", "high", "Unbounded sprintf into buffer"),
            "gets": ("BUFFER_OVERRUN", "critical", "Use of unsafe gets() function"),
            "scanf(": ("BUFFER_OVERRUN", "medium", "Potential buffer overflow via scanf"),
            "free(": ("USE_AFTER_FREE", "medium", "Memory deallocation - check for UAF"),
            "printf(": ("FORMAT_STRING", "medium", "Printf call - check format string safety"),
            "malloc(": ("NULLPTR_DEREFERENCE", "low", "Malloc call - check NULL return"),
        }
        
        findings = []
        for pattern, (check_id, severity, detail) in danger_patterns.items():
            if pattern in prompt:
                findings.append(
                    {
                        "check_id": check_id,
                        "severity": severity,
                        "file": "unknown",
                        "line": 0,
                        "function_name": "unknown",
                        "title": f"Potential {check_id.replace('_', ' ').title()}",
                        "detail": f"[OFFLINE] {detail}",
                    }
                )
                if len(findings) >= 3:
                    break
                    
        return json.dumps(
            {
                "summary": "[offline] Heuristic scan without LLM. Found pattern-based warnings.",
                "findings": findings,
            }
        )

    def _offline_summary(self, file_path: Path, snippet: str, reason: str) -> tuple[str, list[StaticFinding]]:
        # Build offline response directly from snippet content
        response = self._offline_response(snippet)
        return self._parse_llm_response(response, default_file=str(file_path))

    def _parse_llm_response(
        self, response: str, default_file: str
    ) -> tuple[str, list[StaticFinding]]:
        import re
        
        # Try to extract JSON from various formats
        json_str = response.strip()
        
        # Try to extract JSON from markdown code blocks
        json_block_match = re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?```', json_str)
        if json_block_match:
            json_str = json_block_match.group(1).strip()
        
        # Try to find JSON object directly
        if not json_str.startswith('{'):
            json_match = re.search(r'(\{[\s\S]*\})', json_str)
            if json_match:
                json_str = json_match.group(1)
        
        try:
            payload = json.loads(json_str)
        except json.JSONDecodeError as e:
            # Log the parse error for debugging
            return f"JSON parse error: {e}. Raw response: {response[:200]}", []

        findings_payload = payload.get("findings", []) or []
        findings: list[StaticFinding] = []
        
        # Validate severity values
        valid_severities = {"info", "low", "medium", "high", "critical"}
        
        for item in findings_payload:
            # Skip malformed entries
            if not isinstance(item, dict):
                continue
                
            severity = item.get("severity", "medium").lower()
            if severity not in valid_severities:
                severity = "medium"  # Default to medium if invalid
            
            # Extract line number safely
            try:
                line = int(item.get("line", 0))
            except (ValueError, TypeError):
                line = 0
            
            findings.append(
                StaticFinding(
                    tool="langgraph-llm",
                    check_id=item.get("check_id", "LLM_HEURISTIC"),
                    file=item.get("file", default_file),
                    line=line,
                    severity=severity,
                    title=item.get("title", "Potential vulnerability"),
                    detail=item.get("detail", ""),
                    function_name=item.get("function_name"),
                    raw_payload=item,
                )
            )
        return payload.get("summary", ""), findings

    def _compose_summary(
        self, target: TargetProjectConfig, summaries: list[str], findings: list[StaticFinding]
    ) -> str:
        finding_counts: dict[str, int] = {}
        for finding in findings:
            finding_counts.setdefault(finding.severity, 0)
            finding_counts[finding.severity] += 1
        breakdown = ", ".join(f"{sev}:{count}" for sev, count in finding_counts.items()) or "no issues"
        combined_summary = (
            f"Static analysis for {target.name} inspected {len(summaries)} snippets. "
            f"Severity breakdown: {breakdown}. "
            f"Highlights: {' | '.join(summaries)[:500]}"
        )
        return combined_summary

    def _log_event(
        self,
        run_ctx: RunContext,
        store: LocalRunStore | None,
        message: str,
    ) -> None:
        """Log an INFO message to the run log."""
        if store:
            store.log_event(run_ctx, message)
    
    def _log_tool(
        self,
        run_ctx: RunContext,
        store: LocalRunStore | None,
        tool: str,
        action: str,
        detail: dict[str, Any],
    ) -> None:
        if store:
            store.log_tool_call(run_ctx, tool, action, detail)
        else:
            log_file = run_ctx.logs_dir / "tool_calls.jsonl"
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "project": run_ctx.project,
                "run_id": run_ctx.run_id,
                "tool": tool,
                "action": action,
                "detail": detail,
            }
            with log_file.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(entry) + "\n")

    def _relative_posix(self, path: Path, root: Path) -> str:
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        return str(PurePosixPath(rel))

    @staticmethod
    def _is_c_cpp(path: Path) -> bool:
        return path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

    @staticmethod
    def _harness_patterns(target: TargetProjectConfig) -> list[str]:
        patterns = [str(PurePosixPath(ft)) for ft in target.fuzz_targets]
        patterns.extend(str(PurePosixPath(p)) for p in target.harness_globs)
        return patterns

    # =========================================================================
    # Generic LLM Completion (for patcher and other agents)
    # =========================================================================

    async def completion(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> str:
        """
        Generic LLM completion for any agent.

        Args:
            messages: List of messages with 'role' and 'content' keys
            model: Model to use (defaults to runtime config)
            temperature: Sampling temperature
            max_tokens: Maximum tokens for this call (optional)

        Returns:
            String response from LLM
        """
        if not self._llm:
            # Offline fallback
            return self._offline_completion_response(messages)

        # Build prompt from messages
        prompt_parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                prompt_parts.append(f"[System]: {content}")
            elif role == "assistant":
                prompt_parts.append(f"[Assistant]: {content}")
            else:
                prompt_parts.append(f"[User]: {content}")

        full_prompt = "\n\n".join(prompt_parts)

        # Check token budget
        prompt_tokens_est = len(full_prompt.split()) * 1.3
        if self._tokens_used + prompt_tokens_est > self._max_tokens:
            raise RuntimeError(
                f"Token budget exceeded: {self._tokens_used}/{self._max_tokens}"
            )

        try:
            loop = asyncio.get_running_loop()
            completion = await loop.run_in_executor(
                None, lambda: self._llm.invoke(full_prompt)
            )
            self._tokens_used += int(prompt_tokens_est * 2)
            return completion.content if hasattr(completion, "content") else str(completion)
        except Exception as e:
            error_str = str(e).lower()
            # Check for errors that should fall back to offline mode
            offline_triggers = [
                "401", "api_key", "invalid",  # Auth errors
                "429", "quota", "rate_limit", "insufficient_quota",  # Quota errors
            ]
            if any(trigger in error_str for trigger in offline_triggers):
                return self._offline_completion_response(messages)
            self._retry_count += 1
            if self._retry_count >= self._max_retries:
                raise RuntimeError(f"LLM call failed after {self._max_retries} retries: {e}")
            raise

    def _offline_completion_response(self, messages: list[dict[str, str]]) -> str:
        """Generate an offline response for testing."""
        # Extract system and user messages
        system_msg = ""
        user_msg = ""
        for msg in messages:
            if msg.get("role") == "system":
                system_msg = msg.get("content", "")
            elif msg.get("role") == "user":
                user_msg = msg.get("content", "")

        # Check if this is a patching request
        if "patch" in system_msg.lower() or "fix" in system_msg.lower():
            # Extract file path and line from user message
            import re
            file_match = re.search(r"\*\*File:\*\*\s*(\S+)", user_msg)
            line_match = re.search(r"\*\*Line:\*\*\s*(\d+)", user_msg)
            
            file_path = file_match.group(1) if file_match else "unknown.c"
            line_num = int(line_match.group(1)) if line_match else 1

            return f"""```yaml
analysis: |
  [OFFLINE MODE] Unable to analyze vulnerability without LLM credentials.
  This is a placeholder response for testing.
fix_strategy: |
  [OFFLINE MODE] No fix strategy available in offline mode.
file_path: {file_path}
patch: |
  @@ -{line_num},1 +{line_num},1 @@
   // [OFFLINE] Placeholder patch - no changes made
```"""

        return "[OFFLINE MODE] LLM credentials not configured."

