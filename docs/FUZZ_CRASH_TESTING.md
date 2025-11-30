# Fuzz Crash Testing After Patching

## Summary

After a patch is applied, the CRS:
1. **Rebuilds** the project from the working copy (patched source)
2. **Finds** the correct fuzzer binary per crash harness
3. **Tests** each crash against its corresponding **recompiled** fuzzer binary

This ensures crashes are tested against the **patched code**, not the original.

## How It Works: The Recompilation Flow

### Step-by-Step Process

```
1. Patch Applied to working_copy/src/vuln.c
          ↓
2. Build Script Runs in working_copy/
   └─> Compiles working_copy/src/vuln.c + fuzz/vuln_fuzzer.c
   └─> Creates working_copy/build/vuln_fuzzer (LINKED TO PATCHED CODE)
          ↓
3. _find_fuzzer_binary_for_harness() finds working_copy/build/vuln_fuzzer
          ↓
4. Crash inputs run against working_copy/build/vuln_fuzzer
   └─> The fuzzer binary contains THE PATCHED CODE
```

### Why This Works

The build script (e.g., `build.sh`) compiles the fuzzer binary from source files:

```bash
# From example-c-target/build.sh
$CLANG -fsanitize=fuzzer,address \
    src/vuln.c fuzz/vuln_fuzzer.c \
    -o build/vuln_fuzzer
```

When run in the **working copy**, it reads `working_copy/src/vuln.c` (the PATCHED file) and creates a fuzzer binary that includes the patched code.

## Code Flow

### 1. Patch Application & Rebuild (`patching.py:335-350`)

```python
# Step 1: Apply patch to working copy
patch_result = applier.apply_patch(file_path, parsed_patch.patch)

# Step 2: Rebuild from working copy (RECOMPILES with patched source)
working_copy_dir = working_copy_mgr.get_working_copy_path()
build_success, build_error = await self._rebuild_project(
    target, working_copy_dir, run_ctx  # <-- cwd=working_copy
)
```

### 2. Rebuild Function (`patching.py:408-438`)

```python
async def _rebuild_project(self, target, source_dir, run_ctx):
    result = await asyncio.to_thread(
        subprocess.run,
        build_script,
        shell=True,
        cwd=source_dir,  # <-- RUNS IN WORKING COPY
        ...
    )
```

### 3. Fuzzer Binary Discovery (`patching.py:490-528`)

```python
def _find_fuzzer_binary_for_harness(self, source_dir, target, harness_name):
    # Finds binary in source_dir/build/ (working copy)
    # Prefers exact match (vuln_fuzzer) over partial (vuln)
    candidates = [
        harness_name,              # Exact: vuln_fuzzer
        f"fuzzer_{harness_name}",  # LibFuzzerRunner: fuzzer_vuln_fuzzer
    ]
```

### 4. Per-Crash Testing (`patching.py:365-380`)

```python
for crash in crashes:
    # Find CORRECT binary for this crash's harness
    fuzzer_binary = self._find_fuzzer_binary_for_harness(
        working_copy_dir, target, crash.harness
    )
    crash_test = await self._test_crash(run_ctx, fuzzer_binary, crash)
```

## Key Points

| Aspect | Status | Details |
|--------|--------|---------|
| Original source modified? | ✅ NO | All changes in working_copy |
| Fuzzer recompiled? | ✅ YES | Build runs in working_copy |
| Per-harness binary? | ✅ YES | Each crash uses its harness's fuzzer |
| Binary has patched code? | ✅ YES | Compiled from working_copy/src/ |

## Logging Evidence

From actual CRS run:
```
[PatchingPipeline] Rebuilding from working copy: .../artifacts/patching/working_copy
[PatchingPipeline]   (Original source is NOT modified)
[PatchingPipeline] Testing 1 crashes against PATCHED binary...
[PatchingPipeline]   Crashes grouped by harness: ['vuln_fuzzer']
[PatchingPipeline]   Using fuzzer binary for harness 'vuln_fuzzer': .../working_copy/build/vuln_fuzzer
[PatchingPipeline]     ✓ Confirmed: binary is from patched working copy
```

## Tests

| Test | Verifies |
|------|----------|
| `test_find_fuzzer_binary_prefers_fuzzer_over_standalone` | Finds `vuln_fuzzer` not `vuln` |
| `test_fuzzer_binary_recompiled_from_patched_source` | Binary is compiled from working_copy |
| `test_working_copy_fuzzer_not_original` | Binary path contains "working_copy" |
| `test_find_fuzzer_binary_for_harness` | Correct binary per harness |

## Code References

| Component | File | Lines |
|-----------|------|-------|
| Patch application & crash testing | `trata/src/pipelines/patching.py` | 335-395 |
| Rebuild function | `trata/src/pipelines/patching.py` | 408-438 |
| Fuzzer binary discovery (per-harness) | `trata/src/pipelines/patching.py` | 490-528 |
| Crash model (has `harness` field) | `trata/src/storage/models.py` | 95-106 |

