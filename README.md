## Mini CRS (`trata/`)

This directory contains an intentionally small but end‑to‑end Cyber Reasoning System that mirrors the overall shape of the RoboDuck CRS while focusing on a single OSS‑Fuzz project at a time.

### High‑level Architecture

1. **Target intake** – The orchestrator consumes a `TargetProjectConfig` (name, OSS-Fuzz repo, build recipe, fuzz target metadata). The config can be provided via CLI, environment variables, or a manifest file.
2. **Workspace manager** – Each run gets a dedicated working directory under `trata/data/<project>/<timestamp>` where we check out sources, build artifacts, static-analysis logs, crash reports, and LLM reasoning traces.
3. **Build + dependency preparation** – A `ProjectBuilder` normalizes the OSS-Fuzz build scripts (Docker or local) and emits a `BuildArtifacts` record (compiled binaries, compile_commands.json, Infer capture DB path, etc.).
4. **Static analysis jobs** – The orchestrator schedules both:
   - **LLM-based reasoning** powered by a LangGraph-style agent (see `agents/static_analysis.py`). The agent explicitly logs every “tool call” (`source_locator`, `source_reader`, `llm_static_analysis`) in `tool_calls.jsonl` while streaming prompts defined in `prompts/static_analysis.py`.
   - **Deterministic analyzers** such as Facebook Infer (runner in `tools/fbinfer_runner.py`). Results are normalized into a shared schema (`storage.models.StaticFinding`).
5. **Evidence store + journaling** – `LocalRunStore` persists run logs, tool-call traces, raw LLM inputs/outputs, and final reports as JSON bundles under `trata/data`. These traces are first-class grading artifacts.
6. **Future hooks** – The layout reserves room for dynamic fuzzing, POV generation, and patching stages so this mini CRS can grow toward full RoboDuck parity.

### Agentic Framework

We adopt **LangGraph** to wire LLM tools into deterministic control-flow:

```
Target summary ─▶ Code reader ─▶ Vulnerability heuristics ─┐
                    ▲            ▼                          │
        Context fetcher ◀──── Remediation memory ◀──────────┘
```

LangGraph gives us:
- Reusable tool abstractions (Git, build logs, Infer findings, raw source reads).
- Stateful reasoning loops with guardrails (budgeting, retries, tool whitelists).
- JSONL journaling of every thought/tool invocation for auditing.
- Easy transition to multi-agent scenarios (triage ↔️ patching).

### Repository Layout

```
trata/
├── README.md               # this document
├── data/                   # per‑run artifacts (git repos, Infer DBs, LLM traces)
├── main.py                 # CLI entry point
└── src/
    ├── config.py           # dataclasses for targets, storage, runtime knobs
    ├── orchestrator/       # MiniCRSOrchestrator and job wiring
    ├── agents/             # LangGraph‑powered agent definitions
    ├── pipelines/          # Static analysis + (future) fuzzing/triage flows
    ├── storage/            # LocalRunStore and normalized result schemas
    └── tools/              # External integrations (Infer, builders, LLM clients, etc.)
```

### Next Steps

- Flesh out dynamic fuzzing and triage pipelines.
- Add POV + patching stages, reusing the same storage contracts.
- Integrate Azure/GCS upload paths for sharing corpora and reports.

