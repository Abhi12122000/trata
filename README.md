## Mini CRS (Heavily vibe-coded)

This package hosts a lightweight but full-loop Cyber Reasoning System modeled after the RoboDuck architecture. It ingests a single OSS-Fuzz project and produces static-analysis findings (LLM + Infer) plus fuzzing crashes (libFuzzer) together with complete reasoning logs.

---

## Architecture

| Stage | Responsibilities | Key Modules |
| --- | --- | --- |
| Target intake | Parse CLI config, collect harness metadata, locate sources. | `main.py`, `src/config.py` |
| Workspace manager | Create `trata/data/<project>/<timestamp>` and surface run context to every component. | `src/storage/local_store.py` |
| Build layer | Clone or reuse sources, execute build recipe, write `build.log`. | `src/tools/project_builder.py` |
| Static analysis | LLM agent (LangGraph-style) + Facebook Infer, both logged and merged. | `src/agents/static_analysis.py`, `src/tools/llm_client.py`, `src/tools/fbinfer_runner.py` |
| **Fuzzing** | Build fuzzer with sanitizers, run libFuzzer, collect crashes. | `src/pipelines/fuzzing.py`, `src/tools/libfuzzer_runner.py`, `src/tools/corpus_manager.py` |
| **Patching** | Generate LLM patches for findings, apply, test against crashes. | `src/pipelines/patching.py`, `src/agents/patcher.py`, `src/tools/patch_applier.py` |
| Persistence | Emit `StaticAnalysisBatch`, `FuzzingBatch`, `PatchingBatch` + JSONL run logs for grading/auditing. | `src/storage/models.py`, `src/storage/local_store.py` |

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

### Quick Start (Example Target)

Run the complete CRS pipeline (static analysis + fuzzing) on the example target:

```bash
python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --fuzz-target fuzz/packet_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --fuzzing-time 60
```

This will:
1. Build the target project
2. Run static analysis (LLM + Infer)
3. Build and run fuzzers on all specified harnesses
4. **Automatically deduplicate crashes by stack trace**
5. **Generate LLM patches for static analysis findings**
6. **Test patches against fuzz crashes**
7. Save results to `trata/data/example-c/<timestamp>/`

### Running on Your Own Project

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
       ├── static_analysis.json    # normalized findings for downstream agents
       └── fuzzing/                # Fuzzing results (if enabled)
           ├── {harness}_results.json # Per-harness results
           ├── combined_results.json  # Combined results
           └── deduplicated_crashes.json # ⭐ Unique crashes (for patcher)
   ```
   The orchestrator now writes `static_analysis.json` even if the build or analysis fails (summary indicates the failure reason).
   
   **Note:** Crash deduplication runs automatically after fuzzing completes. See [FUZZING_IMPLEMENTATION.md](FUZZING_IMPLEMENTATION.md) for details.

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

**Single harness:**
```bash
python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --fuzzing-time 60
```

**Multiple harnesses (recommended):**
```bash
python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --fuzz-target fuzz/packet_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --fuzzing-time 60
```

This intentionally vulnerable C program compiles quickly and is ideal for testing both static analysis (Infer) and fuzzing (libFuzzer). The fuzzer should find crashes within seconds due to the deliberate memory bugs.

**Target project structure:**
```
example-c-target/
├── src/
│   ├── vuln.c         # Vulnerable library code (6 bugs)
│   ├── vuln.h         # Header file
│   └── main.c         # Standalone test binary (not used in fuzzing)
├── fuzz/
│   ├── vuln_fuzzer.c  # Main fuzzer (tests all bugs)
│   └── packet_fuzzer.c # Focused fuzzer (tests process_packet)
└── build.sh           # Build script
```

**Fuzzing-specific flags:**
- `--fuzz-target`: Can be repeated for multiple harnesses
- `--no-fuzzing`: skip fuzzing entirely
- `--fuzzing-time 60`: total fuzzing time (divided among harnesses)
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

## Data Flow & Output Locations

### Complete Command (with Patching)

**Run the full CRS pipeline (static analysis → fuzzing → patching):**

```bash
OPENAI_API_KEY=sk-... python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --fuzz-target fuzz/packet_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --fuzzing-time 60
```

**Run WITHOUT patching (static analysis + fuzzing only):**

```bash
python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --no-patching
```

**Run WITHOUT LLM (Infer static analysis + fuzzing only):**

```bash
python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --no-static-llm --no-patching
```

### Output Files

After a run, results are in `trata/data/<project>/<timestamp>/`:

```
artifacts/
├── static_analysis.json      # Combined Infer + LLM findings
├── infer/
│   └── report.json           # Raw Infer output
├── fuzzing/                   # Fuzzing results (if enabled)
│   ├── {harness}_results.json # Per-harness results (all crashes)
│   ├── combined_results.json  # Combined results from all harnesses
│   ├── deduplicated_crashes.json # Unique crashes (one per bug) - for patcher
│   ├── corpus_{harness}/       # Per-harness corpus
│   │   ├── seeds/             # Seed inputs
│   │   └── crashes/           # Crash inputs by dedup token
│   │       └── <dedup_token>/
│   │           └── <crash_id> # Raw crash input bytes
│   └── fuzzer.log             # libFuzzer stdout/stderr
└── patching/                  # Patching results (if enabled)
    ├── patching_results.json  # Full patching results with test outcomes
    ├── llm_interactions.jsonl # Log of all LLM interactions for patcher
    ├── patches/               # Individual patch files (unified diff)
    │   └── patch_{n}_{file}.patch
    ├── patched_files/         # ⭐ SAVED PATCHED SOURCE FILES
    │   └── patch_{n}_{file}_{finding_id}
    ├── working_copy/          # Working copy with ALL cumulative patches
    │   └── src/               # Can be used directly for manual testing
    └── backups/               # Empty after successful run (deleted after restore)
```

### 📍 Where to Find What

| What You Need | Location |
|---------------|----------|
| **Run logs** | `logs/run.log` |
| **All tool calls/LLM interactions** | `logs/tool_calls.jsonl` |
| **Static analysis findings** | `artifacts/static_analysis.json` |
| **Fuzzing crashes (deduplicated)** | `artifacts/fuzzing/deduplicated_crashes.json` |
| **Raw crash inputs** | `artifacts/fuzzing/corpus_{harness}/crashes/<token>/<id>` |
| **Patching summary** | `artifacts/patching/patching_results.json` |
| **Generated patches (diff format)** | `artifacts/patching/patches/` |
| **Patched source files** | `artifacts/patching/patched_files/` |
| **Working copy (all patches applied)** | `artifacts/patching/working_copy/` |
| **LLM prompts/responses (patcher)** | `artifacts/patching/llm_interactions.jsonl` |
| **Infer raw output** | `artifacts/infer/report.json` |
| **Build log** | `artifacts/build/build.log` |

### Key Files Explained

- `static_analysis.json`: All static findings (Infer + LLM)
- `fuzzing/deduplicated_crashes.json`: **Unique crashes only** (one per bug signature) - **used by patcher**
- `fuzzing/corpus_{harness}/crashes/<token>/<id>`: Raw crash inputs for reproduction
- `patching/patching_results.json`: Patch generation/application/test results
- `patching/llm_interactions.jsonl`: Full log of patcher LLM calls (prompts + responses)
- **`patching/patched_files/`**: ⭐ Individual patched files saved after each successful patch
- **`patching/working_copy/`**: ⭐ Complete source tree with ALL patches applied cumulatively

### Docker Volume Mounts

When running Infer via Docker, the CRS mounts three volumes:

1. **`-v {source_dir}:/src`**: Project source code (read-only inside container, but writable on host for build artifacts)
2. **`-v {source_dir}:{source_dir}`**: Duplicate mount so Infer's `chdir()` calls to host paths succeed
3. **`-v {output_dir}:/out`**: Analysis results directory (Infer writes `report.json` here, which is accessible on the host at `trata/data/<project>/<timestamp>/artifacts/infer/report.json`)

All results are automatically saved to the host filesystem—no manual copying needed.

---

---

## Logging Architecture

### Where Logs Are Written

All logs are written to `trata/data/<project>/<timestamp>/`:

| Log File | Purpose | Contents |
|----------|---------|----------|
| `logs/run.log` | Main event log | Timestamped events from all pipeline stages |
| `logs/tool_calls.jsonl` | Tool/LLM calls | Every external call (LLM, source reader, etc.) as JSONL |
| `logs/llm_summary.json` | LLM summary | Static analysis LLM responses |
| `logs/fuzzing.log` | Fuzzer output | libFuzzer stdout/stderr |
| `artifacts/patching/llm_interactions.jsonl` | Patcher LLM | Full prompts and responses for patch generation |

### Log Format

**run.log** format:
```
2025-11-30T09:36:18.649115+00:00 [example-c/20251130-093522] [INFO] [PatchingPipeline] Rebuilding from working copy...
```

**tool_calls.jsonl** format:
```json
{"timestamp": "...", "project": "...", "tool": "source_locator", "action": "list_files", "detail": {...}}
```

### What Gets Logged

| Stage | Events Logged |
|-------|---------------|
| **Build** | Start, compile_commands creation, success/failure |
| **Static Analysis** | LLM prompts, responses, findings, Infer execution |
| **Fuzzing** | Build, run start, crashes found, seeds found, deduplication |
| **Patching** | Patch generation, validation, application, build, crash tests, rollback |

### Viewing Logs

```bash
# Full run log
cat trata/data/example-c/<timestamp>/logs/run.log

# Just patching events
grep "PatchingPipeline" trata/data/example-c/<timestamp>/logs/run.log

# LLM interactions
cat trata/data/example-c/<timestamp>/artifacts/patching/llm_interactions.jsonl | python -m json.tool

# Tool calls (JSON Lines)
cat trata/data/example-c/<timestamp>/logs/tool_calls.jsonl | head -5 | python -m json.tool
```

---

## Patching Architecture

### How Patching Works (V1)

1. **Working Copy Creation**: A fresh copy of the source is created in `artifacts/patching/working_copy/`. The **original source is NEVER modified**.

2. **Patch Generation**: For each static analysis finding, the LLM generates a unified diff patch.

3. **Cumulative Application**: Patches are applied **cumulatively** to the working copy:
   - Patch 1 is applied
   - Patch 2 is applied on top of Patch 1
   - etc.
   
4. **Build & Test**: After each patch:
   - The working copy is rebuilt
   - All fuzz crashes are re-run to test if they're fixed
   
5. **Rollback on Failure**: If a patch fails to apply or breaks the build:
   - The file is restored from backup
   - Next patch is attempted
   - Emergency restore from original source if backup fails

6. **Save Patched Files**: Each successfully patched file is saved to `patched_files/` for review.

### Patch Testing Flow

```
For each finding:
  1. Create backup of file
  2. Apply patch to working copy
  3. Rebuild project
     - On failure: rollback, try next
  4. Test against ALL fuzz crashes
  5. Log results (crashes fixed vs remaining)
  6. Save patched file to patched_files/
  7. Keep patch in working copy (cumulative)
```

### What's NOT in V1

- No feedback loop (failed patches don't get refined)
- No sequence alignment (patches must apply cleanly)
- No inter-patch conflict resolution

---

## To-Dos:-

#### General:- 
- Add logging throughout the steps of the CRS. These should be logged into stdout
- Add LLM usage limits to all llm agents carefully.
- Separate out each individual LLM agent's feature-flag. I should be able to disable static analysis LLM without individually, while still keeping other agents running.
- Add more (complicated and less explicit) target projects to run trata CRS on.

#### Patcher related:-
- (Done) Implement v1 patcher, which just takes in a static analysis bug report and the relevant target source file, and outputs a patch in unified diff format.
- (Done) A next step applies that patch, and re-runs ALL fuzz crashes on it (but immediately doesn't do anything if some/all fuzz crashes continue to fail).
- (Future) Implement feedback loop for failed patches
- (Future) Add sequence alignment for fuzzy patch application (like theori's CRS)

#### Fuzzer related:-
- (Future To-Do) Implement triage fuzz crash type functionality (need a lot of improvement for it)
- (Punted for now) Add memcpy bug that static analysis wasn't able to fix; I want to verify that fuzzing fixes that.
- (Won't do) Run fuzzing in a dockerized container
- (Done) Fix our target project example to separate out the fuzz harness, so we don't have to do an ifndef in the main function
- (Done) implement multi-harness fuzzing.
- (Done) verify that the fuzzing crash report is in a format that the patching step can use effectively, and it can run its patched output against the fuzz crash seeds.

#### Static Analysis related:-
- For LLM-based static analysis, implement AST parser etc., to create function-level static analysis targets
- Integrate above with entire CRS correctly. 

## Future Work:-
- implement vuln scoring, analyze_vuln, enhance patching agent, pov generation, and triage fuzz crash.

## Tests

Run all unit tests:

```bash
# Run all tests
OPENAI_API_KEY=test pytest trata/tests/ -v

# Static analysis tests
OPENAI_API_KEY=test pytest trata/tests/test_llm_client.py -v

# Fuzzing tests
pytest trata/tests/test_fuzzing.py -v

# Crash deduplication tests
pytest trata/tests/test_crash_deduplicator.py -v

# Patcher tests
pytest trata/tests/test_patcher.py -v
```

## Documentation

- **[FUZZING_IMPLEMENTATION.md](FUZZING_IMPLEMENTATION.md)**: Complete documentation of the fuzzing system, including architecture, components, crash deduplication, and integration with the patcher agent.


