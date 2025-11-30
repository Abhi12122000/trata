## Mini CRS (`trata/`)

This package hosts a lightweight but full-loop Cyber Reasoning System modeled after the RoboDuck architecture. It ingests a single OSS-Fuzz project and produces static-analysis findings (LLM + Infer) plus fuzzing crashes (libFuzzer) together with complete reasoning logs.

---

## Architecture at a Glance

| Stage | Responsibilities | Key Modules |
| --- | --- | --- |
| Target intake | Parse CLI config, collect harness metadata, locate sources. | `main.py`, `src/config.py` |
| Workspace manager | Create `trata/data/<project>/<timestamp>` and surface run context to every component. | `src/storage/local_store.py` |
| Build layer | Clone or reuse sources, execute build recipe, write `build.log`. | `src/tools/project_builder.py` |
| Static analysis | LLM agent (LangGraph-style) + Facebook Infer, both logged and merged. | `src/agents/static_analysis.py`, `src/tools/llm_client.py`, `src/tools/fbinfer_runner.py` |
| **Fuzzing** | Build fuzzer with sanitizers, run libFuzzer, collect crashes. | `src/pipelines/fuzzing.py`, `src/tools/libfuzzer_runner.py`, `src/tools/corpus_manager.py` |
| Persistence | Emit `StaticAnalysisBatch`, `FuzzingBatch` + JSONL run logs for grading/auditing. | `src/storage/models.py`, `src/storage/local_store.py` |

---

## Repository Layout

```
trata/
├── README.md                 # this document
├── main.py                   # CLI entry point
├── data/                     # per-run outputs (logs + artifacts)
├── example-c-target/         # sample vulnerable C project with fuzzer
├── example-libpng/           # sample project (sources + harness)
├── nginx/                    # sample project (OSS-Fuzz harness only)
└── src/
    ├── config.py             # Target/Runtime configs
    ├── orchestration/        # MiniCRSOrchestrator
    ├── agents/               # LLM agents
    ├── pipelines/            # Static-analysis + Fuzzing pipelines
    ├── storage/              # LocalRunStore + models
    ├── tools/                # Builder, Infer runner, LLM client, LibFuzzer runner
    └── prompts/              # Static-analysis prompt
```

---

## Installation

### 1. Python Environment

```bash
# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or: venv\Scripts\activate  # On Windows

# Install dependencies
cd trata
pip install -r requirements.txt
```

**Requirements:**
- Python ≥ 3.9 (tested on 3.9, 3.10, 3.11, 3.12)
- macOS ARM64 (Apple Silicon) or x86_64 Linux

### 2. Docker (for Infer)

The CRS uses Docker to run Facebook Infer in a consistent environment. Install Docker Desktop:

- **macOS**: Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
- **Linux**: `sudo apt-get install docker.io` or equivalent

The first run will automatically build the Infer Docker image (`trata-infer:1.2.0`) from `trata/docker/infer/Dockerfile`. Subsequent runs reuse the cached image.

### 3. OpenAI API Key (Optional)

For LLM-based static analysis:

```bash
export OPENAI_API_KEY="sk-..."
```

Without an API key, the LLM agent falls back to an offline heuristic (no findings, but runs complete successfully for testing).

### 4. Build Tools

Install whatever your target project requires:
- **C/C++**: `clang`, `gcc`, `cmake`, `autoconf`, `make`, etc.
- **Java**: `maven`, `gradle`, JDK
- Check your target's `build.sh` or `Dockerfile` for specific requirements

### 5. Clang with libFuzzer Support (for Fuzzing)

For fuzzing to work, you need `clang` with `-fsanitize=fuzzer` support:

```bash
# macOS (via Homebrew)
brew install llvm
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

# Ubuntu/Debian
sudo apt-get install clang

# Verify fuzzer support
clang -fsanitize=fuzzer -x c -c /dev/null -o /dev/null && echo "libFuzzer supported!"
```

If clang doesn't support `-fsanitize=fuzzer`, the CRS will skip fuzzing and only run static analysis.

---

## Prerequisites Summary

| Requirement | Notes |
| --- | --- |
| Python ≥ 3.9 | Use a virtual environment (see Installation above). |
| Docker Desktop | Required for Infer analysis. The CRS builds the image automatically. |
| Clang with libFuzzer | Required for fuzzing. See installation above. |
| Build toolchain | Depends on target project (see target-specific notes below). |
| OpenAI API key (optional) | Set `OPENAI_API_KEY` env var. Without it, LLM analysis is skipped. |

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

### example-c smoke test (with fuzzing)
```bash
python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --fuzzing-time 60
```
This intentionally vulnerable C program compiles quickly and is ideal for testing both static analysis (Infer) and fuzzing (libFuzzer). The fuzzer should find crashes within seconds due to the deliberate memory bugs.

**Fuzzing-specific flags:**
- `--no-fuzzing`: skip fuzzing entirely
- `--fuzzing-time 60`: run fuzzer for 60 seconds total
- `--fuzzing-timeout 30`: per-execution timeout
- `--fuzzing-workers 2`: parallel fuzzer jobs

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

## Testing

Run the unit tests:

```bash
# From the trata/ directory
pytest tests/test_llm_client.py -v
```

The test suite verifies:
- LLM client fallback behavior (offline mode)
- Build artifact exclusion
- Tool call logging

---

## Data Flow & Next Steps

### Output Files

After a run, results are in `trata/data/<project>/<timestamp>/`:

```
artifacts/
├── static_analysis.json      # Combined Infer + LLM findings
├── infer/
│   └── report.json           # Raw Infer output
└── fuzzing/                   # Fuzzing results (if enabled)
    ├── fuzzing_results.json  # Crashes, seeds, stats
    ├── crashes/              # Crash inputs by dedup token
    │   └── <dedup_token>/
    │       └── <crash_id>    # Raw crash input bytes
    ├── corpus_data/          # Seed corpus
    │   ├── seeds/            # All seeds
    │   └── crashes/          # Copy of crashes
    └── fuzzer.log            # libFuzzer stdout/stderr
```

**Key files:**
- `static_analysis.json`: All static findings (Infer + LLM)
- `fuzzing/fuzzing_results.json`: Fuzzing summary with crashes
- `fuzzing/crashes/<token>/<id>`: Raw crash inputs for reproduction

### Docker Volume Mounts

When running Infer via Docker, the CRS mounts three volumes:

1. **`-v {source_dir}:/src`**: Project source code (read-only inside container, but writable on host for build artifacts)
2. **`-v {source_dir}:{source_dir}`**: Duplicate mount so Infer's `chdir()` calls to host paths succeed
3. **`-v {output_dir}:/out`**: Analysis results directory (Infer writes `report.json` here, which is accessible on the host at `trata/data/<project>/<timestamp>/artifacts/infer/report.json`)

All results are automatically saved to the host filesystem—no manual copying needed.

---

## Next Steps & Contributions

- Extend pipelines to coverage collection, frontier discovery, fuzz triage, POV production, and patch bundling.
- Integrate Azure/GCS upload options for corpora/results sharing.
- Contributions are welcome—please follow the existing structure so logging and storage remain consistent.

## Tests

Run all unit tests:

```bash
# Static analysis tests
pytest trata/tests/test_llm_client.py -v

# Fuzzing tests
pytest trata/tests/test_fuzzing.py -v
```


