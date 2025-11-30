# Patcher Agent (V1)

## Technical Summary

The **V1 Patcher Agent** generates security patches using an LLM. Given a static analysis finding (file, line, vulnerability type), it extracts source context and prompts an LLM to produce a unified diff patch.

### What V1 Does

| Capability | Implementation |
|------------|----------------|
| **Source Context Extraction** | Reads ±50 lines around the vulnerable line |
| **Prompt Construction** | Zero-shot prompt with finding details + source snippet |
| **Patch Generation** | LLM outputs YAML with `analysis`, `fix_strategy`, `patch` fields |
| **YAML Parsing** | Extracts unified diff from LLM response |
| **Patch Application** | Tries `patch -p1` first, falls back to manual line-by-line |
| **Build Verification** | Runs build script, logs success/failure |
| **Crash Testing** | Re-runs all fuzz crash inputs against patched binary |
| **Token Budgeting** | Enforces per-patch (4000) and total (20000) token limits |

### What V1 Does NOT Do

- No feedback loop (failed patches are not refined)
- No sequence alignment (patches must apply cleanly)
- No conflict resolution between patches
- No semantic verification of fixes

## Incremental Patching

Within a single CRS run, patches are applied **cumulatively**:

```
Finding 1: Generate patch from working_copy (0 previous patches)
  → Apply patch → Rebuild → Test crashes
  → Keep patch in working_copy

Finding 2: Generate patch from working_copy (1 previous patch)
  → Apply patch → Rebuild → Test crashes
  → Keep patch in working_copy

Finding 3: Generate patch from working_copy (2 previous patches)
  → Apply patch → Rebuild → Test crashes
  → Keep patch in working_copy
```

**Key insight**: Each patch sees source code with ALL previous patches applied. This allows later patches to build on earlier fixes.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      PatchingPipeline                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌──────────────┐ │
│  │ WorkingCopy     │    │  PatcherAgent   │    │ PatchApplier │ │
│  │ Manager         │    │                 │    │              │ │
│  │                 │    │  - extract ctx  │    │  - parse     │ │
│  │  - initialize   │───▶│  - build prompt │───▶│  - validate  │ │
│  │  - backup       │    │  - call LLM     │    │  - apply     │ │
│  │  - restore      │    │  - parse YAML   │    │  - rollback  │ │
│  │  - save patched │    │                 │    │              │ │
│  └─────────────────┘    └─────────────────┘    └──────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Patch Flow

```
1. Create working copy of source
2. For each static finding:
   a. Extract source context from working copy
   b. Build LLM prompt (system + user)
   c. Call LLM, get YAML response
   d. Parse patch from YAML
   e. Create file backup
   f. Apply patch (try `patch`, then manual)
   g. Rebuild project
   h. If build fails: rollback, continue
   i. Test against all fuzz crashes
   j. Log results (fixed vs remaining)
   k. Save patched file to patched_files/
3. Output: patching_results.json + patched files
```

## Token Budget

| Setting | Default | Description |
|---------|---------|-------------|
| `max_tokens_per_patch` | 4000 | Max tokens per LLM call |
| `max_total_tokens` | 20000 | Total budget for all patches |

When budget is exceeded, remaining findings are skipped.

## Output Files

```
artifacts/patching/
├── patching_results.json      # Summary with test results
├── llm_interactions.jsonl     # Full LLM prompts/responses
├── patches/                   # Unified diff files
│   └── patch_{n}_{file}.patch
├── patched_files/             # Individual patched files
│   └── patch_{n}_{file}_{finding_id}
├── working_copy/              # Full source with ALL patches
│   └── src/...
└── backups/                   # Empty after successful run
```

## LLM Prompt Structure

**System Prompt**: Instructions for patch generation (YAML format, unified diff, etc.)

**User Prompt**:
```
Vulnerability Type: {vuln_type}
File: {file_path}
Line: {line_number}

SOURCE CONTEXT:
```
{source_lines_with_line_numbers}
>>> {vulnerable_line_marker}
```

FUZZ CRASH INFO (if available):
- Signal: {signal}
- Stack trace: {stack_trace}

Generate a patch to fix this vulnerability.
```

## Rollback Mechanism

If patch application or build fails:

1. Restore file from backup (stored in artifacts/patching/backups/)
2. Continue to next finding
3. Emergency restore from original source if backup is corrupted

**Original source is NEVER modified** - all operations happen on the working copy.

## Testing Patches

After each successful patch:

1. Find fuzzer binary in working copy build
2. For each crash input:
   - Run: `fuzzer crash_input`
   - Capture exit code and stderr
   - Check if crash still occurs
3. Log: `Crash tests: X fixed, Y remaining`

## Configuration

In `PatcherConfig`:
```python
context_lines: int = 50      # Lines before/after vuln
max_retries: int = 2         # LLM call retries
model: str = "gpt-4o"        # LLM model
max_tokens_per_patch: int = 4000
max_total_tokens: int = 20000
```

## Future Work (V2+)

- Feedback loop: Re-prompt LLM when patch fails
- Sequence alignment: Apply patches that don't match exactly
- Conflict resolution: Handle overlapping patches
- Semantic verification: Check fix correctness beyond build success

