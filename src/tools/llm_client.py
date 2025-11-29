from __future__ import annotations

import asyncio
import fnmatch
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from ..config import RuntimeConfig, TargetProjectConfig
from ..prompts import STATIC_ANALYSIS_PROMPT
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

    def __init__(self, runtime_config: RuntimeConfig, max_files: int = 4, max_lines: int = 200) -> None:
        self.runtime = runtime_config
        self.max_files = max_files
        self.max_lines = max_lines
        self._llm = ChatOpenAI(model=runtime_config.langgraph_model) if ChatOpenAI else None
        self._tokens_used = 0
        self._max_tokens = runtime_config.llm_budget_tokens
        self._max_retries = 3
        self._retry_count = 0

    async def run_static_review(
        self,
        target: TargetProjectConfig,
        build: BuildArtifacts,
        run_ctx: RunContext,
        store: LocalRunStore | None = None,
    ) -> tuple[str, Sequence[StaticFinding]]:
        candidate_files, skipped = self._select_candidate_files(target, build)
        self._log_tool(
            run_ctx,
            store,
            "source_locator",
            "selected",
            {
                "files": [str(p) for p in candidate_files],
                "skipped": skipped,
                "reason": (
                    "C/C++ sources prioritized; harness globs excluded; fallback to breadth-first scan"
                ),
            },
        )

        summaries: list[str] = []
        findings: list[StaticFinding] = []

        for file_path in candidate_files:
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

            prompt = STATIC_ANALYSIS_PROMPT.format(
                project=target.name,
                fuzz_target=target.fuzz_target,
                file_path=str(relative_file),
                notes="First pass static heuristics",
                code_snippet=snippet,
                max_findings=3,
                max_lines=self.max_lines,
            )

            # Check token budget before invoking
            prompt_tokens_est = len(prompt.split()) * 1.3  # rough estimate
            if self._tokens_used + prompt_tokens_est > self._max_tokens:
                self._log_tool(run_ctx, store, "llm_static_analysis", "budget_exceeded", {
                    "file": str(file_path),
                    "tokens_used": int(self._tokens_used),
                    "budget": self._max_tokens,
                    "skipped": True,
                })
                break  # Stop processing more files
            
            try:
                response_text = await self._invoke_llm(prompt)
                self._tokens_used += int(prompt_tokens_est * 2)  # rough: prompt + response
                self._retry_count = 0  # reset on success
            except Exception as e:
                self._retry_count += 1
                if self._retry_count >= self._max_retries:
                    self._log_tool(run_ctx, store, "llm_static_analysis", "max_retries_exceeded", {
                        "file": str(file_path),
                        "error": str(e),
                        "retries": self._retry_count,
                    })
                    break
                # Continue to next file on retry
                continue
            
            self._log_tool(run_ctx, store, "llm_static_analysis", "invoke", {
                "file": str(file_path),
                "prompt_tokens_estimate": int(prompt_tokens_est),
                "tokens_used_total": int(self._tokens_used),
                "response": response_text[:8000],  # keep logs bounded
            })

            summary, snippet_findings = self._parse_llm_response(
                response_text,
                default_file=str(relative_file),
            )
            summaries.append(summary)
            findings.extend(snippet_findings)

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

        def should_skip(path: Path) -> bool:
            rel = self._relative_posix(path, build.source_dir)
            if not self._is_c_cpp(path):
                skipped.append(f"{rel}:non-cpp")
                return True
            if rel == target.fuzz_target or rel.startswith(f"{target.fuzz_target}/"):
                skipped.append(f"{rel}:fuzz_target")
                return True
            for pattern in harness_patterns:
                if fnmatch.fnmatch(rel, pattern):
                    skipped.append(f"{rel}:harness")
                    return True
            return False

        for path in build.source_dir.rglob("*"):
            if len(selected) >= self.max_files:
                break
            if not path.is_file():
                continue
            if should_skip(path):
                continue
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
        # Simple heuristic fallback that mimics JSON output.
        danger_tokens = ["strcpy", "memcpy", "sprintf", "gets", "scanf("]
        risk = [tok for tok in danger_tokens if tok in prompt]
        findings = []
        if risk:
            findings.append(
                {
                    "check_id": "heuristic-unsafe-call",
                    "severity": "medium",
                    "file": "unknown",
                    "line": 0,
                    "title": f"Use of {'/'.join(risk)}",
                    "detail": "Detected potentially unsafe call in offline mode.",
                }
            )
        return json.dumps(
            {
                "summary": "[offline] static scan executed without LLM credentials.",
                "findings": findings,
            }
        )

    def _parse_llm_response(
        self, response: str, default_file: str
    ) -> tuple[str, list[StaticFinding]]:
        try:
            payload = json.loads(response)
        except json.JSONDecodeError:
            payload = {"summary": response, "findings": []}

        findings_payload = payload.get("findings", []) or []
        findings: list[StaticFinding] = []
        for item in findings_payload:
            findings.append(
                StaticFinding(
                    tool="langgraph-llm",
                    check_id=item.get("check_id", "llm-heuristic"),
                    file=item.get("file", default_file),
                    line=int(item.get("line", 0)),
                    severity=item.get("severity", "medium"),
                    title=item.get("title", "Potential vulnerability"),
                    detail=item.get("detail", ""),
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
        patterns = [str(PurePosixPath(target.fuzz_target))]
        patterns.extend(str(PurePosixPath(p)) for p in target.harness_globs)
        return patterns

