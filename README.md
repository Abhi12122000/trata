# Mini CRS

A lightweight **Cyber Reasoning System** that automatically discovers and patches security vulnerabilities. It combines static analysis (LLM + Infer), fuzzing (libFuzzer), and LLM-based patch generation.

## What is a CRS?

A CRS is an automated system that finds and fixes software bugs without human help. This implementation:
- Analyzes source code for vulnerabilities (static analysis)
- Generates crash inputs to find bugs (fuzzing)
- Creates patches to fix the bugs (LLM-based patching)
- Tests patches against crashes (verification)

---

## Quick Start

```bash
# 1. Setup
cd trata
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Run on example target
OPENAI_API_KEY=sk-... python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --fuzz-target fuzz/packet_fuzzer.c \
  --harness-glob "fuzz/*" \
  --build-script "bash build.sh" \
  --fuzzing-time 60

# 3. View results
ls trata/data/example-c/<timestamp>/
```

---

## Prerequisites

| Requirement | Installation |
|-------------|--------------|
| Python ≥ 3.9 | Use virtual environment |
| Docker | For Infer static analysis |
| Clang with libFuzzer | `brew install llvm` (macOS) |
| OpenAI API key (optional) | `export OPENAI_API_KEY=sk-...` |

Without an API key, the CRS runs in offline mode (Infer only, placeholder patches).

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `--name` | Project name |
| `--local-checkout` | Path to source code |
| `--fuzz-target` | Path to fuzz harness (can repeat) |
| `--harness-glob` | Glob to exclude harness files from analysis |
| `--build-script` | Build command (executed in source dir) |
| `--fuzzing-time` | Total fuzzing time in seconds |
| `--no-fuzzing` | Skip fuzzing |
| `--no-patching` | Skip patching |
| `--no-static-llm` | Skip LLM static analysis (Infer only) |

---

## Output

Results are saved to `trata/data/<project>/<timestamp>/`:

| Path | Contents |
|------|----------|
| `logs/run.log` | Event log |
| `artifacts/static_analysis.json` | Findings |
| `artifacts/fuzzing/deduplicated_crashes.json` | Unique crashes |
| `artifacts/patching/patched_files/` | Patched source files |
| `artifacts/patching/working_copy/` | Full source with all patches |

---

## Running Tests

```bash
# From project root (aixcc-afc-archive/)
cd /path/to/aixcc-afc-archive
source venv/bin/activate

# All tests
OPENAI_API_KEY=test pytest trata/tests/ -v

# Specific test files
OPENAI_API_KEY=test pytest trata/tests/test_patcher.py -v           # Patching tests
OPENAI_API_KEY=test pytest trata/tests/test_fuzzing.py -v           # Fuzzing tests
pytest trata/tests/test_crash_deduplicator.py -v                     # Dedup tests
OPENAI_API_KEY=test pytest trata/tests/test_llm_client.py -v        # LLM client tests

# Run a SINGLE test
OPENAI_API_KEY=test pytest trata/tests/test_patcher.py::TestPatcherAgent::test_extract_source_context -v

# With DEBUG output (shows internal values)
DEBUG=1 OPENAI_API_KEY=test pytest trata/tests/test_patcher.py -v -s
```

### Debug Mode

Set `DEBUG=1` to see verbose output from tests:

```bash
# See debug prints for a specific test
DEBUG=1 OPENAI_API_KEY=test pytest trata/tests/test_patcher.py::TestPatcherAgent::test_extract_source_context -v -s
```

Note: `-s` flag is required to see print output.

---

## Documentation

| Document | Contents |
|----------|----------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, pipeline stages |
| [docs/PATCHING.md](docs/PATCHING.md) | Patcher agent technical details |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and fixes |
| [docs/FUZZ_CRASH_TESTING.md](docs/FUZZ_CRASH_TESTING.md) | How crashes are tested after patching |
| [docs/LLM_API_USAGE.md](docs/LLM_API_USAGE.md) | Using LLM API credits for patching |
| [FUZZING_IMPLEMENTATION.md](FUZZING_IMPLEMENTATION.md) | Fuzzing system details |

---

## Key Features

- **Incremental Patching**: Each patch sees previous patches' changes
- **Working Copy Isolation**: Original source is never modified
- **Token Budgeting**: Prevents runaway LLM costs
- **Crash Deduplication**: Stack trace-based grouping
- **Comprehensive Logging**: Every tool call and LLM interaction logged

---

## Example Run Output

```
============================================================
CRS Run Complete: example-c (20251130-102728)
============================================================
Summary: Static analysis: 3 findings. Fuzzing: 97 crashes, 12 new seeds. Patching: 3 patches generated
Static Analysis: 3 findings
Fuzzing: 97 crashes, 12 new seeds
Patching: 3 patches generated, 3 applied, 3 tested
============================================================
```
