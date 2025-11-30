# Fuzzing Results Interpretation Guide

## Directory Structure

After a fuzzing run, results are stored in:
```
trata/data/<project>/<run_id>/artifacts/fuzzing/
├── fuzzing_results.json    # Summary and metadata
├── crashes.log             # Human-readable crash log
└── corpus_data/
    ├── seeds/              # Final seed corpus
    └── crashes/            # Crash inputs organized by dedup token
        └── <dedup_token>/
            └── <crash_id>   # Raw crash input (binary)
```

## Understanding `fuzzing_results.json`

```json
{
  "project": "example-c",
  "run_id": "20251130-020417",
  "harness": "fuzz/vuln_fuzzer.c",
  "fuzzer_binary": "/path/to/fuzzer",
  "duration_seconds": 10.4,
  "seeds_initial": 3,        # Seeds at start
  "seeds_final": 4,          # Seeds at end
  "seeds_found": 1,          # New seeds discovered
  "crashes_found": 38,       # Total unique crashes
  "crashes": [...]           # Array of crash objects
}
```

### Crash Object Structure

Each crash in the `crashes` array contains:
- `crash_id`: SHA1 hash of the input (unique identifier)
- `input_path`: Full path to the crash input file
- `input_size`: Size in bytes
- `dedup_token`: First 16 chars of SHA1 (for deduplication grouping)
- `harness`: Name of the harness that found it
- `timestamp`: When it was found
- `signal`: Signal that caused crash (SIGSEGV, SIGABRT, etc.)
- `stack_trace`: AddressSanitizer stack trace (truncated in JSON)

## Crash Input Files

**Location**: `corpus_data/crashes/<dedup_token>/<crash_id>`

These are **raw binary files** containing the exact input that triggered the crash.

**To view a crash input:**
```bash
# Hex dump
xxd <crash_file>

# Size
wc -c <crash_file>

# Reproduce crash
./fuzzer <crash_file>
```

**Example**: A crash file might contain just `\x03` (3 bytes) - this is the minimal input that triggers the bug.

## Deduplication

Crashes are grouped by `dedup_token` (first 16 chars of SHA1). This groups similar crashes together, but **different dedup tokens = different crash types**.

In the example run:
- 38 crashes found
- Multiple dedup tokens = multiple distinct bug types
- Each dedup token bucket can contain multiple crash inputs (up to `max_crashes_per_bucket`)

## Ideal Fuzzing Time

For a small target like `example-c`:
- **10-30 seconds**: Good for quick testing
- **1-5 minutes**: Better coverage, more crashes
- **10+ minutes**: Diminishing returns for simple targets

For real-world projects:
- **Hours to days**: Typical for production fuzzing
- Coverage plateaus after initial rapid growth

## Reading Stack Traces

The `stack_trace` field contains AddressSanitizer output. Key parts:
- `ERROR: AddressSanitizer: <error_type>` - Type of bug
- `READ/WRITE of size X` - Memory access that triggered it
- `#0`, `#1`, `#2` - Stack frames (most recent first)
- File names and line numbers point to the bug location

