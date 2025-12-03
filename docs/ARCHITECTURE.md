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
                         ┌────────────────────────┐
                         │     Target Project     │
                         │   (Source + Harnesses) │
                         └───────────┬────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │        Build           │
                         │  (compile_commands.json│
                         │   + fuzzer binaries)   │
                         └───────────┬────────────┘
                                     │
               ┌─────────────────────┴─────────────────────┐
               │                                           │
               ▼                                           ▼
  ┌────────────────────────┐                ┌────────────────────────┐
  │    Static Analysis     │                │        Fuzzing         │
  │   (LLM + Infer)        │                │      (libFuzzer)       │
  │                        │                │                        │
  │  AST parsing           │                │  Build fuzzer          │
  │  Per-function LLM      │                │  Run with sanitizers   │
  │  Merge findings        │                │  Collect crashes       │
  └───────────┬────────────┘                └───────────┬────────────┘
              │                                         │
              ▼                                         ▼
     ┌────────────────┐                       ┌────────────────┐
     │   Findings     │                       │    Crashes     │
     │ (vuln reports) │                       │ (deduplicated) │
     └────────┬───────┘                       └────────┬───────┘
              │                                        │
              └──────────────────┬─────────────────────┘
                                 │
                                 ▼
                   ┌────────────────────────────┐
                   │     Patching Pipeline      │
                   │                            │
                   │  For each finding:         │
                   │   1. Extract ±50 lines     │
                   │   2. LLM generates patch   │
                   │   3. Apply (fuzzy match)   │
                   │   4. Rebuild project       │
                   │   5. Test against crashes  │
                   └─────────────┬──────────────┘
                                 │
                                 ▼
                   ┌────────────────────────────┐
                   │    Patched source code     │
                   │ saved in working_copy/ dir │
                   └────────────────────────────┘
```


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
2. **Build**: Execute build, generate `compile_commands.json`
3. **Analysis** (parallel):
   - **Static Analysis**: Run Infer + LLM per-function analysis → Findings
   - **Fuzzing**: Build fuzzers with sanitizers, run libFuzzer → Crashes
4. **Deduplication**: Group crashes by unique stack signature (top 3 frames)
5. **Patching**: For each finding:
   - Extract source context (±50 lines)
   - LLM generates unified diff patch
   - Apply patch (exact → fuzzy → manual fallback)
   - Rebuild from working copy
   - Test against deduplicated crashes
6. **Output**: Findings, crashes, patches, patched source code

## Key Design Decisions

1. **Working Copy Isolation**: Patches are applied to a working copy, never the original source
2. **Incremental Patching**: Each patch builds on previous patches
3. **Docker for Infer**: Ensures consistent static analysis environment
4. **JSONL Logging**: Every LLM call and tool action is logged for auditability
5. **Token Budgeting**: Prevents runaway LLM costs




