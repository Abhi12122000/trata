# AST Parsing for Function-Level Analysis

This document describes the AST parsing infrastructure added in Phase 1 for per-function LLM analysis.

## Overview

The mini-CRS uses **tree-sitter** to parse C source files and extract function definitions. This enables per-function LLM analysis (Phase 2), improving analysis granularity and reducing token usage compared to whole-file analysis.

## Tools Used

| Component | Package | Version | Purpose |
|-----------|---------|---------|---------|
| tree-sitter | `tree-sitter` | 0.22.x | Parser generator / AST builder |
| tree-sitter-c | `tree-sitter-c` | 0.21.x | C language grammar |

**Why tree-sitter?**
- Fast incremental parsing
- Produces accurate concrete syntax trees
- Used by Theori's CRS (proven approach)
- Language-agnostic design (can add C++ later)
- Handles complex C syntax (macros, GCC extensions, etc.)

## Architecture

```
trata/src/analysis/
├── __init__.py          # Module exports
├── data.py              # Data structures (SourceFunction, ParsedFile, SourceRange)
└── c_parser.py          # C parser with tree-sitter + regex fallback
```

### Data Structures

**`SourceFunction`** - Represents a parsed function:
```python
@dataclass
class SourceFunction:
    name: str           # e.g., "process_packet"
    file_path: str      # e.g., "src/vuln.c"
    start_line: int     # 1-indexed
    end_line: int       # 1-indexed
    signature: str      # e.g., "void process_packet(const uint8_t *data, size_t size)"
    body: str           # Full function code including signature
    byte_range: SourceRange  # For precise slicing
    is_small: bool      # True if < 10 lines (for clubbing)
```

**`ParsedFile`** - Represents a parsed source file:
```python
@dataclass
class ParsedFile:
    path: str
    source: str
    functions: list[SourceFunction]
    parse_errors: list[str]
    
    # Helper methods
    get_function_by_name(name) -> SourceFunction
    get_function_at_line(line) -> SourceFunction
    get_clubbable_groups() -> list[list[SourceFunction]]
```

## Usage

```python
from trata.src.analysis import parse_c_file

# Parse a file
parsed = parse_c_file("src/vuln.c")

# Access functions
for func in parsed.functions:
    print(f"{func.name}: lines {func.start_line}-{func.end_line}")
    print(f"  Small: {func.is_small}")
    print(f"  Body:\n{func.body}")

# Find function by name
func = parsed.get_function_by_name("process_packet")

# Find function at a specific line (useful for crash analysis)
func = parsed.get_function_at_line(42)

# Get clubbable groups (small adjacent functions)
groups = parsed.get_clubbable_groups()
```

## Supported C Patterns

| Pattern | Example | Supported |
|---------|---------|-----------|
| Basic function | `void foo(void)` | ✅ |
| Single pointer return | `int *foo(void)` | ✅ |
| Double pointer return | `char **foo(void)` | ✅ |
| Function pointer return | `int (*foo(void))(int)` | ✅ |
| Callback parameter | `void foo(void (*cb)(int))` | ✅ |
| Static functions | `static void foo(void)` | ✅ |
| Inline functions | `inline void foo(void)` | ✅ |
| Variadic functions | `void foo(const char *, ...)` | ✅ |
| K&R style (old C) | `int foo(x, y) int x; int y;` | ✅ |
| `__attribute__` annotations | `__attribute__((noreturn)) void foo()` | ✅ |
| Macro return types | `MY_TYPE foo(void)` | ✅ |

## Known Limitations

### Not Supported

1. **C++ constructs** - Classes, templates, lambdas, namespaces
   - Solution: Will add `tree-sitter-cpp` in future if needed

2. **Preprocessor-defined functions** - `#define FUNC(x) ...`
   - Reason: tree-sitter parses raw source, not preprocessed code
   - Impact: Minimal for typical C code

3. **Function-like macros** - Macros that look like functions
   - Reason: Not actual function definitions in the AST
   - Impact: None (we only want real functions)

### Edge Cases

1. **Very large files** (>100K lines)
   - Performance is O(n) for line index building
   - Should still be fast, but not tested at scale

2. **Files with syntax errors**
   - tree-sitter is error-tolerant and will parse what it can
   - Unparseable sections are skipped with warnings

3. **Unicode in source code**
   - Handled with `errors="replace"` encoding
   - Byte offsets may be off for non-ASCII code

## Regex Fallback

If tree-sitter is not available, the parser falls back to regex-based parsing:

```python
# The fallback handles:
# - Basic function patterns
# - Static/inline modifiers
# - Common return types

# It does NOT handle:
# - Nested parentheses in parameters (callback params)
# - Complex pointer declarators
# - K&R style functions
```

The fallback is mainly for development environments without tree-sitter installed.

## Integration with Static Analysis

AST parsing is fully integrated with static analysis (Phase 2):

```
LLM Static Analysis starting
AST parsing enabled (tree-sitter available)
AST parsing: 7 functions in 3 files (3 small, 4 large)
Function clubbing: 1 groups of small functions combined
Function-level analysis: 6 units to analyze
Analyzing unit 1/6: src/vuln.c (clubbed: use_after_free_example, null_deref_example, double_free_example)
Analyzing unit 2/6: src/vuln.c:process_packet (lines 55-82)
...
```

**How it works:**
1. Parse all candidate files to extract functions
2. Group small adjacent functions (<10 lines each) into "clubbed" units
3. Each large function becomes its own unit
4. LLM is called once per unit with a function-specific prompt
5. Files with no functions use file-level fallback analysis

## Small Function Clubbing

Functions with < 10 lines are marked as `is_small`. Adjacent small functions are "clubbed" together to reduce LLM calls while maintaining analysis quality:

```python
# Example: vuln.c has 3 small adjacent functions
groups = parsed.get_clubbable_groups()
# Returns: [['use_after_free_example', 'null_deref_example', 'double_free_example']]
# Total: 22 lines - analyzed together in 1 LLM call
```

**Clubbing rules:**
- Functions must be <10 lines each
- Functions must be adjacent (within 5 lines of each other)
- Combined size must be <50 lines
- Large functions break the chain (not included in groups)

**Example analysis units for `example-c-target`:**

| Unit | Functions | Lines | Type |
|------|-----------|-------|------|
| 1 | use_after_free_example, null_deref_example, double_free_example | 18-47 | Clubbed |
| 2 | process_packet | 55-82 | Individual |
| 3 | resize_buffer | 90-115 | Individual |
| 4 | log_message | 123-156 | Individual |
| 5 | main | 12-43 | Individual |
| 6 | vuln.h | 1-21 | File-level (no functions) |

## Testing

Run parser tests:
```bash
# All parser tests
DEBUG=1 pytest trata/tests/test_c_parser.py -v -s

# Run a specific test
pytest trata/tests/test_c_parser.py::TestCParser::test_parse_pointer_return -v
```

## Files Modified in Phase 1

| File | Changes |
|------|---------|
| `trata/requirements.txt` | Added tree-sitter dependencies |
| `trata/src/analysis/__init__.py` | **NEW** - Module exports |
| `trata/src/analysis/data.py` | **NEW** - Data structures |
| `trata/src/analysis/c_parser.py` | **NEW** - C parser |
| `trata/src/tools/llm_client.py` | Added AST parsing integration (read-only) |
| `trata/tests/test_c_parser.py` | **NEW** - 25 unit tests |

