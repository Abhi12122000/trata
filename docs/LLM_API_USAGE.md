# Using LLM API Credits for Patching

## Quick Answer

**No code changes needed!** Just set the `OPENAI_API_KEY` environment variable. The patcher agent will automatically use real API calls instead of placeholder patches.

## How It Works

### 1. LLM Client Initialization (`llm_client.py:32-46`)

```python
# File: trata/src/tools/llm_client.py

def __init__(self, runtime_config: RuntimeConfig, ...):
    try:
        self._llm = ChatOpenAI(model=runtime_config.langgraph_model)
    except Exception:
        # No API key or invalid config - run in offline mode
        self._llm = None
```

**Behavior:**
- If `OPENAI_API_KEY` is set and valid → `ChatOpenAI` initializes → real API calls
- If `OPENAI_API_KEY` is missing/invalid → `self._llm = None` → offline mode

### 2. Patcher Agent Usage (`patching.py:110`)

```python
# File: trata/src/pipelines/patching.py

self.llm = llm_client or LangGraphClient(runtime_config=runtime_config)
```

The patching pipeline creates a `LangGraphClient` which automatically detects API availability.

### 3. Completion Method (`llm_client.py:354-417`)

```python
async def completion(self, messages, model, ...):
    if not self._llm:
        # Offline fallback
        return self._offline_completion_response(messages)
    
    # Real API call
    completion = await loop.run_in_executor(
        None, lambda: self._llm.invoke(full_prompt)
    )
```

**Fallback Triggers:**
- No API key → offline mode
- API errors (401, 429, quota) → offline mode
- Other errors → retry up to 3 times, then raise

### 4. Offline Mode (`llm_client.py:419-452`)

When offline, generates placeholder patches:

```yaml
analysis: |
  [OFFLINE MODE] Unable to analyze vulnerability without LLM credentials.
fix_strategy: |
  [OFFLINE MODE] No fix strategy available in offline mode.
file_path: src/vuln.c
patch: |
  @@ -10,1 +10,1 @@
   // [OFFLINE] Placeholder patch - no changes made
```

**These placeholders are NOT applied** - they're just logged for testing.

## Running with API Credits

### Step 1: Set API Key

```bash
export OPENAI_API_KEY=sk-...
```

Or inline:

```bash
OPENAI_API_KEY=sk-... python -m trata.main ...
```

### Step 2: Run CRS

```bash
# Full run with patching (uses API)
OPENAI_API_KEY=sk-... python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --build-script "bash build.sh" \
  --fuzzing-time 60
```

### Step 3: Verify API Usage

Check logs for:
- `[PatcherAgent] Generating patch for: ...` (not offline messages)
- Real patch diffs (not placeholder `[OFFLINE]` patches)
- Token usage: `Token budget: 1929/20000 used`

## Disabling Static Analysis LLM

### Option 1: CLI Flag (Recommended)

```bash
--no-static-llm
```

This disables LLM-based static analysis but keeps:
- ✅ Infer static analysis
- ✅ Fuzzing
- ✅ Patching (with LLM)

**Example:**
```bash
OPENAI_API_KEY=sk-... python -m trata.main \
  --name example-c \
  --local-checkout trata/example-c-target \
  --fuzz-target fuzz/vuln_fuzzer.c \
  --build-script "bash build.sh" \
  --no-static-llm  # Disable LLM static analysis
```

### Option 2: Code Check

The static analysis pipeline checks `runtime.enable_static_llm`:

```python
# File: trata/src/pipelines/static_analysis.py:44

if self.runtime.enable_static_llm:
    for agent in self.agents:
        llm_findings.extend(await agent.run(ctx))
else:
    self.store.log_event(run_ctx, "LLM static analysis disabled via --no-static-llm")
```

## Configuration

### Patcher Model Selection

Default: `gpt-4o` (set in `PatcherConfig`)

To change:
```bash
--patcher-model gpt-4o-mini
```

Or in code:
```python
patcher_config = PatcherConfig(model="gpt-4o-mini")
```

### Token Budgets

| Setting | Default | Description |
|---------|---------|-------------|
| `max_tokens_per_patch` | 4000 | Max tokens per LLM call |
| `max_total_tokens` | 20000 | Total budget for all patches |
| `max_llm_calls_per_patch` | 5 | Max LLM interactions per patch |
| `max_patches_per_run` | 10 | Hard limit on patches |

These are in `PatcherConfig` (`trata/src/agents/patcher.py:30-37`).

## Troubleshooting

### Issue: Still Getting Offline Patches

**Check:**
1. Is `OPENAI_API_KEY` set? `echo $OPENAI_API_KEY`
2. Is the key valid? Test with: `curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"`
3. Check logs for: `[PatcherAgent] BUDGET EXCEEDED` or `LLM CALL LIMIT REACHED`

### Issue: API Errors (429, Quota)

The code automatically falls back to offline mode for:
- `401` (unauthorized)
- `429` (rate limit)
- `quota`, `rate_limit`, `insufficient_quota`

**Solution:** Add credits or wait for rate limit reset.

### Issue: Want to Force Offline Mode

**Option 1:** Don't set `OPENAI_API_KEY`
**Option 2:** Set invalid key: `OPENAI_API_KEY=invalid`

## Code References

| Component | File | Lines |
|-----------|------|-------|
| LLM client initialization | `trata/src/tools/llm_client.py` | 32-46 |
| Completion method | `trata/src/tools/llm_client.py` | 354-417 |
| Offline fallback | `trata/src/tools/llm_client.py` | 419-452 |
| Patcher agent | `trata/src/agents/patcher.py` | 85-488 |
| Static analysis LLM toggle | `trata/src/pipelines/static_analysis.py` | 44-49 |
| CLI flag | `trata/main.py` | 71-74 |




