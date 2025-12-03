from __future__ import annotations

import asyncio
import fnmatch
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from ..analysis import ParsedFile, SourceFunction
from ..analysis.c_parser import parse_c_file, is_tree_sitter_available
from ..config import RuntimeConfig, TargetProjectConfig
from ..prompts.static_analysis import build_static_analysis_prompt, build_function_analysis_prompt
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
        
        # Log tree-sitter availability (Phase 1 - informational only)
        if is_tree_sitter_available():
            self._log_event(run_ctx, store, "AST parsing enabled (tree-sitter available)")
        else:
            self._log_event(run_ctx, store, "AST parsing disabled (tree-sitter not available)")
        
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

        # Parse files and extract functions
        parsed_files = self._parse_candidate_files(
            candidate_files, build.source_dir, run_ctx, store
        )

        # Build analysis units (individual functions or clubbed groups)
        analysis_units = self._build_analysis_units(parsed_files, build.source_dir, run_ctx, store)
        
        self._log_event(
            run_ctx, store,
            f"Function-level analysis: {len(analysis_units)} units to analyze"
        )

        summaries: list[str] = []
        findings: list[StaticFinding] = []

        for idx, unit in enumerate(analysis_units):
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
            
            # Extract unit info
            file_path = unit["file_path"]
            relative_file = unit["relative_file"]
            function_names = unit["function_names"]
            line_range = unit["line_range"]
            code_snippet = unit["code"]
            is_clubbed = unit["is_clubbed"]
            
            # Log what we're analyzing
            if is_clubbed:
                self._log_event(
                    run_ctx, store,
                    f"Analyzing unit {idx + 1}/{len(analysis_units)}: "
                    f"{relative_file} (clubbed: {', '.join(function_names)}, lines {line_range})"
                )
            else:
                self._log_event(
                    run_ctx, store,
                    f"Analyzing unit {idx + 1}/{len(analysis_units)}: "
                    f"{relative_file}:{function_names[0]} (lines {line_range})"
                )
            
            self._log_tool(run_ctx, store, "function_analyzer", "unit_selected", {
                "file": relative_file,
                "functions": function_names,
                "lines": line_range,
                "is_clubbed": is_clubbed,
                "code_lines": code_snippet.count("\n") + 1,
            })

            # Build function-level prompt
            prompt = build_function_analysis_prompt(
                project=target.name,
                file_path=relative_file,
                function_names=function_names,
                line_range=line_range,
                code_snippet=code_snippet,
                max_findings=self._max_findings_per_file,
            )

            # Check token budget before invoking
            prompt_tokens_est = len(prompt.split()) * 1.3  # rough estimate
            if self._tokens_used + prompt_tokens_est > self._max_tokens:
                self._log_event(
                    run_ctx, store,
                    f"Token budget exhausted ({int(self._tokens_used)}/{self._max_tokens}). Using offline fallback."
                )
                self._log_tool(run_ctx, store, "llm_static_analysis", "budget_exceeded", {
                    "file": relative_file,
                    "functions": function_names,
                    "tokens_used": int(self._tokens_used),
                    "budget": self._max_tokens,
                    "skipped": True,
                })
                summary, snippet_findings = self._offline_summary(
                    Path(file_path), code_snippet, "[budget exhausted]"
                )
                summaries.append(summary)
                findings.extend(snippet_findings)
                break  # Stop processing
            
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
                        f"Max retries exceeded for {relative_file}:{function_names}: {e}"
                    )
                    self._log_tool(run_ctx, store, "llm_static_analysis", "max_retries_exceeded", {
                        "file": relative_file,
                        "functions": function_names,
                        "error": str(e),
                        "retries": self._retry_count,
                    })
                    summary, snippet_findings = self._offline_summary(
                        Path(file_path), code_snippet, str(e)
                    )
                    summaries.append(summary)
                    findings.extend(snippet_findings)
                    break
                # Continue to next unit on retry
                continue
            
            self._log_tool(run_ctx, store, "llm_static_analysis", "invoke", {
                "file": relative_file,
                "functions": function_names,
                "lines": line_range,
                "prompt_tokens_estimate": int(prompt_tokens_est),
                "tokens_used_total": int(self._tokens_used),
                "llm_calls_made": self._llm_calls_made,
                "response": response_text[:8000],  # keep logs bounded
            })

            summary, snippet_findings = self._parse_llm_response(
                response_text,
                default_file=relative_file,
            )
            
            # Track findings and log
            self._total_findings += len(snippet_findings)
            func_display = ", ".join(function_names) if len(function_names) <= 3 else f"{len(function_names)} functions"
            self._log_event(
                run_ctx, store,
                f"  Found {len(snippet_findings)} findings in {relative_file}:{func_display} "
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

    def _write_functions_log(
        self,
        parsed_files: dict[str, ParsedFile],
        source_dir: Path,
        run_ctx: RunContext,
    ) -> None:
        """
        Write a human-readable log of all extracted functions.
        
        Output file: logs/extracted_functions.txt
        This is useful for debugging and demoing the AST parsing.
        """
        lines = []
        lines.append("=" * 70)
        lines.append("EXTRACTED FUNCTIONS (AST Parsing Results)")
        lines.append("=" * 70)
        lines.append("")
        
        total_funcs = 0
        for file_path_str, parsed in parsed_files.items():
            try:
                rel_path = Path(file_path_str).relative_to(source_dir)
            except ValueError:
                rel_path = Path(file_path_str)
            
            lines.append(f"FILE: {rel_path}")
            lines.append("-" * 50)
            
            if not parsed.functions:
                lines.append("  (no functions found - header file or no definitions)")
            else:
                for func in parsed.functions:
                    total_funcs += 1
                    small_marker = " [SMALL]" if func.is_small else ""
                    lines.append(f"  [{func.start_line}-{func.end_line}] {func.name}{small_marker}")
                    lines.append(f"      Signature: {func.signature}")
                    lines.append(f"      Lines: {func.line_count}")
                    # Show first few lines of body for debugging
                    body_preview = func.body.split('\n')[:3]
                    body_preview_str = '\n'.join(f"        {line}" for line in body_preview)
                    if len(func.body.split('\n')) > 3:
                        body_preview_str += "\n        ..."
                    lines.append(f"      Body preview:")
                    lines.append(body_preview_str)
                    lines.append("")
            
            lines.append("")
        
        lines.append("=" * 70)
        lines.append(f"TOTAL: {total_funcs} functions in {len(parsed_files)} files")
        lines.append("=" * 70)
        
        # Write to file
        log_path = run_ctx.logs_dir / "extracted_functions.txt"
        log_path.write_text("\n".join(lines), encoding="utf-8")

    def _parse_candidate_files(
        self,
        candidate_files: list[Path],
        source_dir: Path,
        run_ctx: RunContext,
        store: LocalRunStore | None,
    ) -> dict[str, ParsedFile]:
        """
        Parse candidate files to extract function information.
        
        Returns:
            Dictionary mapping file paths to their parsed representations.
        """
        parsed_files: dict[str, ParsedFile] = {}
        total_functions = 0
        small_functions = 0
        
        if not is_tree_sitter_available():
            self._log_event(
                run_ctx, store,
                "Skipping function extraction (tree-sitter not available)"
            )
            return parsed_files
        
        for file_path in candidate_files:
            try:
                relative_path = file_path.relative_to(source_dir)
            except ValueError:
                relative_path = file_path
            
            parsed = parse_c_file(file_path)
            if parsed.parse_errors:
                self._log_event(
                    run_ctx, store,
                    f"Parse warnings for {relative_path}: {parsed.parse_errors[:2]}"
                )
            
            parsed_files[str(file_path)] = parsed
            total_functions += parsed.function_count
            small_functions += parsed.small_function_count
        
        # Log AST parsing summary (one line, comprehensive)
        self._log_event(
            run_ctx, store,
            f"AST parsing complete: {total_functions} functions extracted from {len(parsed_files)} files "
            f"({small_functions} small [<{10} lines, clubbable], "
            f"{total_functions - small_functions} large)"
        )
        
        # Write detailed function extraction log for debugging/demoing
        self._write_functions_log(parsed_files, source_dir, run_ctx)
        
        # Log function details to tool_calls for debugging
        self._log_tool(
            run_ctx, store,
            "ast_parser",
            "functions_extracted",
            {
                "total_files": len(parsed_files),
                "total_functions": total_functions,
                "small_functions": small_functions,
                "functions_by_file": {
                    str(Path(path).name): [
                        {
                            "name": f.name,
                            "lines": f"{f.start_line}-{f.end_line}",
                            "line_count": f.line_count,
                            "is_small": f.is_small,
                        }
                        for f in parsed.functions
                    ]
                    for path, parsed in parsed_files.items()
                },
            },
        )
        
        return parsed_files
    
    def _build_analysis_units(
        self,
        parsed_files: dict[str, ParsedFile],
        source_dir: Path,
        run_ctx: RunContext,
        store: LocalRunStore | None,
    ) -> list[dict[str, Any]]:
        """
        Build analysis units from parsed files.
        
        Each unit is either:
        - A single function (for large functions)
        - A group of clubbed small adjacent functions
        - The whole file (if no functions were found)
        
        Returns:
            List of analysis unit dictionaries with:
            - file_path: Absolute path
            - relative_file: Relative path string
            - function_names: List of function names
            - line_range: Line range string
            - code: Code snippet to analyze
            - is_clubbed: Whether this unit is a clubbed group
        """
        units: list[dict[str, Any]] = []
        clubbed_count = 0
        
        for file_path_str, parsed in parsed_files.items():
            file_path = Path(file_path_str)
            try:
                relative_file = str(file_path.relative_to(source_dir))
            except ValueError:
                relative_file = str(file_path)
            
            # If no functions found, fall back to file-level analysis
            if not parsed.functions:
                # Read first N lines as fallback
                snippet = self._read_snippet(file_path)
                if snippet.strip():
                    units.append({
                        "file_path": file_path_str,
                        "relative_file": relative_file,
                        "function_names": ["<file-level>"],
                        "line_range": f"1-{snippet.count(chr(10)) + 1}",
                        "code": snippet,
                        "is_clubbed": False,
                    })
                continue
            
            # Get clubbable groups of small functions
            clubbable_groups = parsed.get_clubbable_groups(max_combined_lines=50)
            clubbed_funcs: set[str] = set()
            
            # Add clubbed groups
            for group in clubbable_groups:
                group_names = [f.name for f in group]
                clubbed_funcs.update(group_names)
                
                # Build combined code snippet
                # Sort by start line to maintain order
                sorted_group = sorted(group, key=lambda f: f.start_line)
                combined_code = "\n\n".join(f.body for f in sorted_group)
                
                # Build line range string
                line_ranges = [f"{f.start_line}-{f.end_line}" for f in sorted_group]
                line_range_str = ", ".join(line_ranges)
                
                units.append({
                    "file_path": file_path_str,
                    "relative_file": relative_file,
                    "function_names": group_names,
                    "line_range": line_range_str,
                    "code": combined_code,
                    "is_clubbed": True,
                })
                clubbed_count += 1
            
            # Add individual large functions (not clubbed)
            for func in parsed.functions:
                if func.name in clubbed_funcs:
                    continue  # Already handled in a clubbed group
                
                units.append({
                    "file_path": file_path_str,
                    "relative_file": relative_file,
                    "function_names": [func.name],
                    "line_range": f"{func.start_line}-{func.end_line}",
                    "code": func.body,
                    "is_clubbed": False,
                })
        
        # Log clubbing summary
        if clubbed_count > 0:
            self._log_event(
                run_ctx, store,
                f"Function clubbing: {clubbed_count} groups of small functions combined"
            )
        
        self._log_tool(
            run_ctx, store,
            "function_analyzer",
            "units_prepared",
            {
                "total_units": len(units),
                "clubbed_groups": clubbed_count,
                "units": [
                    {
                        "file": u["relative_file"],
                        "functions": u["function_names"],
                        "lines": u["line_range"],
                        "clubbed": u["is_clubbed"],
                    }
                    for u in units
                ],
            },
        )
        
        return units

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

