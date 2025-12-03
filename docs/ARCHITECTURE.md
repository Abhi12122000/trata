# Architecture

## What is a CRS?

A **Cyber Reasoning System (CRS)** is an automated software system designed to discover and fix security vulnerabilities without human intervention. Originally developed for DARPA's Cyber Grand Challenge, a CRS combines multiple techniques:

- **Static Analysis**: Examining source code without execution
- **Dynamic Analysis**: Running code to observe behavior
- **Fuzzing**: Automated input generation to find crashes
- **Patch Generation**: Automatically creating fixes for vulnerabilities
- **Patch Testing**: Verifying fixes don't break functionality

## Mini CRS Pipeline

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Target Intake  │────▶│  Static Analysis │────▶│    Fuzzing      │
│  (Build Setup)  │     │  (LLM + Infer)   │     │  (libFuzzer)    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │                         │
                                ▼                         ▼
                        ┌───────────────┐         ┌───────────────┐
                        │   Findings    │         │   Crashes     │
                        └───────────────┘         └───────────────┘
                                │                         │
                                └──────────┬──────────────┘
                                           ▼
                              ┌────────────────────────┐
                              │   Patching Pipeline    │
                              │  (LLM Patch Generation │
                              │   + Crash Testing)     │
                              └────────────────────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │   Patched Source Code  │
                              └────────────────────────┘
```

## Stage Responsibilities

| Stage | What It Does | Key Modules |
|-------|--------------|-------------|
| **Target Intake** | Parse CLI config, locate sources, set up workspace | `main.py`, `src/config.py` |
| **Workspace Manager** | Create `trata/data/<project>/<timestamp>`, provide run context | `src/storage/local_store.py` |
| **Build Layer** | Execute build recipe, generate `compile_commands.json` | `src/tools/project_builder.py` |
| **Static Analysis** | LLM-based analysis + Facebook Infer, merge findings | `src/agents/static_analysis.py`, `src/tools/fbinfer_runner.py` |
| **Fuzzing** | Build fuzzer with sanitizers, run libFuzzer, collect crashes | `src/pipelines/fuzzing.py`, `src/tools/libfuzzer_runner.py` |
| **Crash Deduplication** | Stack trace-based deduplication | `src/tools/crash_deduplicator.py` |
| **Patching** | LLM patch generation, application, crash testing | `src/pipelines/patching.py`, `src/agents/patcher.py` |
| **Persistence** | Emit results + JSONL logs for auditing | `src/storage/models.py` |

## Repository Layout

```
trata/
├── README.md                 # Quick start guide
├── main.py                   # CLI entry point
├── requirements.txt          # Python dependencies
├── docs/                     # Detailed documentation
│   ├── ARCHITECTURE.md       # This file
│   ├── PATCHING.md           # Patcher agent details
│   └── TROUBLESHOOTING.md    # Common issues & fixes
├── data/                     # Per-run outputs (auto-generated)
├── example-c-target/         # Sample vulnerable C project
├── tests/                    # Unit tests
└── src/
    ├── config.py             # Target/Runtime configs
    ├── orchestration/        # MiniCRSOrchestrator
    ├── agents/               # LLM agents (static analysis, patcher)
    ├── pipelines/            # Static analysis, Fuzzing, Patching
    ├── storage/              # LocalRunStore + data models
    ├── tools/                # Builder, Infer, LLM client, LibFuzzer
    └── prompts/              # LLM prompt templates
```

## Data Flow

1. **Input**: Target project path + build script
2. **Build**: Execute build, generate compile database
3. **Static Analysis**: Run Infer + LLM, produce findings
4. **Fuzzing**: Build fuzzers, run with sanitizers, collect crashes
5. **Deduplication**: Group crashes by unique stack signature
6. **Patching**: Generate patches, apply to working copy, test against crashes
7. **Output**: Findings, crashes, patches, patched source code

## Key Design Decisions

1. **Working Copy Isolation**: Patches are applied to a working copy, never the original source
2. **Incremental Patching**: Each patch builds on previous patches
3. **Docker for Infer**: Ensures consistent static analysis environment
4. **JSONL Logging**: Every LLM call and tool action is logged for auditability
5. **Token Budgeting**: Prevents runaway LLM costs




