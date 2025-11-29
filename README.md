## Mini CRS (`trata/`)

This package hosts a lightweight but full-loop Cyber Reasoning System modeled after the RoboDuck architecture. It ingests a single OSS-Fuzz project and produces static-analysis findings (LLM + Infer) together with complete reasoning logs.

---

## Architecture at a Glance

| Stage | Responsibilities | Key Modules |
| --- | --- | --- |
| Target intake | Parse CLI config, collect harness metadata, locate sources. | `main.py`, `src/config.py` |
| Workspace manager | Create `trata/data/<project>/<timestamp>` and surface run context to every component. | `src/storage/local_store.py` |
| Build layer | Clone or reuse sources, execute build recipe, write `build.log`. | `src/tools/project_builder.py` |
| Static analysis | LLM agent (LangGraph-style) + Facebook Infer, both logged and merged. | `src/agents/static_analysis.py`, `src/tools/llm_client.py`, `src/tools/fbinfer_runner.py` |
| Persistence | Emit `StaticAnalysisBatch` + JSONL run logs for grading/auditing. | `src/storage/models.py`, `src/storage/local_store.py` |

---

## Repository Layout

```
trata/
├── README.md                 # this document
├── main.py                   # CLI entry point
├── data/                     # per-run outputs (logs + artifacts)
├── example-libpng/           # sample project (sources + harness)
├── nginx/                    # sample project (OSS-Fuzz harness only)
└── src/
    ├── config.py             # Target/Runtime configs
    ├── orchestration/        # MiniCRSOrchestrator
    ├── agents/               # LLM agents
    ├── pipelines/            # Static-analysis pipeline
    ├── storage/              # LocalRunStore + models
    ├── tools/                # Builder, Infer runner, LLM client
    └── prompts/              # Static-analysis prompt
```

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Python ≥ 3.9 | Recommended: `python -m venv venv && source venv/bin/activate`. |
| Pip packages | Install `langchain-openai`, `openai`, `tiktoken`, `orjson`, etc. (see repo root requirements). |
| Build toolchain | Whatever the project needs (e.g., `cmake`, `autoconf`, compilers, Ninja). |
| Facebook Infer | Either install locally (`brew install infer`) or rely on Docker (`docker pull facebook/infer:latest`). |
| OpenAI credentials (optional) | Set `OPENAI_API_KEY` (+ azure-specific vars if required). Without creds, the LLM client falls back to an offline heuristic so runs still succeed. |

---

## Running the CRS

1. **Prepare the project directory**
   - The directory must contain both the original source code **and** the fuzz harnesses.
   - OSS-Fuzz project folders often contain only harnesses/Dockerfiles (e.g., `oss-fuzz/projects/nginx`). Clone the upstream repo into the same directory or point `--repo` to it so Infer and the LLM can inspect real code.

2. **Invoke the CLI**
   ```bash
   python -m trata.main \
     --name example-libpng \
     --local-checkout trata/example-libpng \
     --fuzz-target contrib/oss-fuzz/libpng_read_fuzzer.cc \
     --harness-glob "contrib/oss-fuzz/*fuzzer*.cc" \
     --build-script "cmake -S . -B build && cmake --build build -j$(sysctl -n hw.ncpu)"
   ```

   **Important flags**
   - `--local-checkout`: reuse an existing directory (skip to let the tool `git clone --repo`).
   - `--fuzz-target`: relative path to the primary harness. Used only for exclusion.
   - `--harness-glob`: additional glob(s) to skip other harness files from analysis.
   - `--build-script`: preferred way of compiling; this is executed verbatim inside the source root.
   - `--workspace`: optionally override the output root (default `trata/data`).
   - `--llm-budget-tokens`: cap total prompt+response tokens (default: 32 000).

3. **Review outputs**
   ```
   trata/data/<project>/<timestamp>/
   ├── logs/
   │   ├── run.log                 # orchestrator events
   │   ├── tool_calls.jsonl        # every source_locator / reader / LLM action
   │   └── llm_summary.{txt,json}  # combined summaries + raw responses
   └── artifacts/
       ├── build/                  # build.log, temp outputs
       ├── infer/                  # Infer report.json, etc.
       └── static_analysis.json    # normalized findings for downstream agents
   ```
   The orchestrator now writes `static_analysis.json` even if the build or analysis fails (summary indicates the failure reason).

---

## Target-Specific Notes

### nginx (only harness files copied)
The `trata/nginx` directory currently contains OSS-Fuzz harness assets but *not* the upstream source. To run the CRS:
1. Clone the official repo into the same directory, e.g. `git clone https://github.com/nginx/nginx.git trata/nginx/src`.
2. Ensure the fuzz harness references files relative to that tree.
3. Provide a build command that compiles in-place, for example:
   ```bash
   python -m trata.main \
     --name nginx \
     --local-checkout trata/nginx \
     --fuzz-target fuzz/http_request_fuzzer.cc \
     --harness-glob "fuzz/*" \
     --build-script "cd src && ./auto/configure --with-debug && make -j$(sysctl -n hw.ncpu)"
   ```
   Infer and the LLM scan everything under `trata/nginx`, so merging harness + sources is sufficient.

### dropbear example
```bash
python -m trata.main \
  --name dropbear \
  --repo https://github.com/mkj/dropbear.git \
  --fuzz-target fuzz/dropbear_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "./configure && make -j$(sysctl -n hw.ncpu)"
```
If your harnesses live in a separate folder, copy them into the checkout before running or pass `--local-checkout` to a combined tree.

---

## LLM Guardrails (Costs & Reliability)

- The static-analysis agent tracks an approximate token budget (`RuntimeConfig.llm_budget_tokens`, default 32k). Once exceeded the agent stops issuing completions and logs a `budget_exceeded` entry.
- Each completion is retried at most three times. Persistent failures log `max_retries_exceeded` and abort the LLM portion instead of burning unlimited credits.
- Remove `OPENAI_API_KEY` to force offline mode; the execution still produces artifacts using heuristic findings so you can grade the run without spending credits.

---

## Troubleshooting

| Symptom | Diagnosis | Fix |
| --- | --- | --- |
| `can't open infra/helper.py` in build log | Provided `--build-script` was ignored in older versions. | Update: builder now prioritizes `--build-script`. |
| `FileNotFoundError: infer` | Infer binary missing. | Install via package manager or rely on Docker (`docker pull facebook/infer`). |
| `openai.RateLimitError / insufficient_quota` | Hit API quota. | Increase credits, lower `--llm-budget-tokens`, or run without API key to use offline mode. |
| Empty `artifacts/static_analysis.json` | Run crashed before persist. | Update to latest; orchestrator now writes an error summary even on failure. |

---

## Next Steps & Contributions

- Extend pipelines to coverage collection, frontier discovery, fuzz triage, POV production, and patch bundling.
- Integrate Azure/GCS upload options for corpora/results sharing.
- Contributions are welcome—please follow the existing structure so logging and storage remain consistent.


