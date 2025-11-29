from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import RunContext, StaticAnalysisBatch


class LocalRunStore:
    """Filesystem-backed persistence used by the mini CRS."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def allocate_run_context(self, project: str) -> RunContext:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        run_root = self.root / project / timestamp
        logs = run_root / "logs"
        artifacts = run_root / "artifacts"
        logs.mkdir(parents=True, exist_ok=True)
        artifacts.mkdir(parents=True, exist_ok=True)
        return RunContext(
            project=project,
            run_id=timestamp,
            root=run_root,
            logs_dir=logs,
            artifacts_dir=artifacts,
        )

    def log_event(self, ctx: RunContext, message: str) -> None:
        log_file = ctx.logs_dir / "run.log"
        with log_file.open("a", encoding="utf-8") as fp:
            fp.write(
                f"{datetime.now(timezone.utc).isoformat()} "
                f"[{ctx.project}/{ctx.run_id}] {message}\n"
            )

    def log_tool_call(
        self,
        ctx: RunContext,
        tool: str,
        action: str,
        detail: dict[str, Any],
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "project": ctx.project,
            "run_id": ctx.run_id,
            "tool": tool,
            "action": action,
            "detail": detail,
        }
        log_file = ctx.logs_dir / "tool_calls.jsonl"
        with log_file.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(entry) + "\n")

    def persist_static_batch(self, ctx: RunContext, batch: StaticAnalysisBatch) -> None:
        out_file = ctx.artifacts_dir / "static_analysis.json"
        payload: dict[str, Any] = {
            "project": batch.project,
            "run_id": batch.run_id,
            "summary": batch.summary,
            "findings": [
                {
                    "tool": f.tool,
                    "check_id": f.check_id,
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "evidence_path": str(f.evidence_path) if f.evidence_path else None,
                    "raw_payload": f.raw_payload,
                }
                for f in batch.findings
            ],
        }
        with out_file.open("w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2)

