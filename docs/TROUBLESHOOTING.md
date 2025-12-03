# Troubleshooting

## Common Issues

### Build Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `can't open infra/helper.py` in build log | OSS-Fuzz helper missing | Use `--build-script` with explicit build command |
| `compile_commands.json` not found | Build didn't generate compile DB | Add `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` or use `bear make` |
| Build fails silently | Check `artifacts/build/build.log` | Look for missing dependencies |

### Docker/Infer Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `FileNotFoundError: infer` | Infer not installed | CRS uses Docker by default - ensure Docker is running |
| `docker-credential-desktop` error | Docker credential helper missing | Install Docker Desktop or disable credential helper |
| Infer finds no bugs | `report.json` empty | Check `compile_commands.json` has absolute paths |
| Infer segfaults | Relative paths in compile DB | Regenerate with absolute paths |

### LLM Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `openai.RateLimitError` | API quota exceeded | Add credits, or run without `OPENAI_API_KEY` |
| `insufficient_quota` | No API credits | Remove `OPENAI_API_KEY` for offline mode |
| Empty LLM findings | Budget exceeded or offline | Check `logs/run.log` for budget messages |
| `TOKEN BUDGET EXHAUSTED` | Hit token limit | Increase `--llm-budget-tokens` |

### Fuzzing Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Fuzzer not built | `clang` missing libFuzzer | Install LLVM via Homebrew: `brew install llvm` |
| `library not found: libclang_rt.fuzzer` | System clang lacks fuzzer | Use Homebrew clang: `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"` |
| No crashes found | Timeout too short or no bugs | Increase `--fuzzing-time` |
| `main()` conflict | Target has `main()` function | Add `#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` guard |

### Patching Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No fuzzer binary found` | Build doesn't create named binary | Check `build/` for executable names |
| Patch fails to apply | Malformed patch or context mismatch | Check `llm_interactions.jsonl` for LLM response |
| Build fails after patch | Patch introduces syntax error | This is logged; patch is rolled back |
| Original source modified | Bug (should not happen) | File issue; working copy should be used |

## Viewing Logs

```bash
# Full run log
cat trata/data/<project>/<timestamp>/logs/run.log

# Filter by component
grep "PatchingPipeline" trata/data/<project>/<timestamp>/logs/run.log
grep "FuzzingPipeline" trata/data/<project>/<timestamp>/logs/run.log
grep "StaticAnalysis" trata/data/<project>/<timestamp>/logs/run.log

# LLM interactions (patcher)
cat trata/data/<project>/<timestamp>/artifacts/patching/llm_interactions.jsonl | python -m json.tool

# Tool calls
cat trata/data/<project>/<timestamp>/logs/tool_calls.jsonl | head -10 | python -m json.tool

# Build log
cat trata/data/<project>/<timestamp>/artifacts/build/build.log
```

## Quick Checks

### Is Docker running?
```bash
docker info
```

### Is clang set up correctly?
```bash
clang -fsanitize=fuzzer -x c -c /dev/null -o /dev/null && echo "libFuzzer supported!"
```

### Is the API key valid?
```bash
curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY" | head -c 100
```

## Getting Help

1. Check `logs/run.log` for error messages
2. Check `artifacts/build/build.log` for build failures
3. Run with `--no-fuzzing --no-patching` to isolate static analysis
4. Run with `--no-static-llm` to test just Infer + fuzzing




