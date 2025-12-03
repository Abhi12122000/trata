"""Static analysis prompt templates for the LLM-based security analyzer."""

# =============================================================================
# Vulnerability Categories (compatible with Infer's check_id format)
# =============================================================================

VULNERABILITY_CATEGORIES = """
## Vulnerability Categories

You should use the following check_id values (compatible with Infer's format):

| check_id | Description | Common Triggers |
|----------|-------------|-----------------|
| BUFFER_OVERRUN | Out-of-bounds read/write | strcpy, memcpy, sprintf without length checks; loops exceeding bounds |
| USE_AFTER_FREE | Dereferencing freed memory | Dangling pointers; callbacks using freed objects |
| NULLPTR_DEREFERENCE | Dereferencing null pointer | Missing malloc/open result checks; cleared pointers |
| MEMORY_LEAK_C | Heap allocation never freed | Early-exit paths; reassigning pointers without free |
| DOUBLE_FREE | Freeing same allocation twice | Two free() without NULL; aliases to same heap block |
| UNINITIALIZED_VALUE | Reading uninitialized memory | Using malloc'd buffers without memset |
| INTEGER_OVERFLOW | Arithmetic wrap/overflow | Size calculations; negative to unsigned casts |
| FORMAT_STRING | Untrusted format string | User input passed to printf/sprintf format arg |
| TYPE_CONFUSION | Wrong type interpretation | Casting void* to incompatible types; union misuse |
| COMMAND_INJECTION | OS command injection | User input in system(), exec(), popen() |
| PATH_TRAVERSAL | File path injection | User-controlled paths without sanitization |
"""

# =============================================================================
# Few-Shot Examples
# =============================================================================

EXAMPLE_INPUT_1 = """
```c
// File: src/parser.c
void process_packet(char *data, size_t len) {
    char buffer[256];
    int offset = *(int*)data;  // Read offset from packet
    
    if (len > 0) {
        memcpy(buffer, data + 4, len - 4);  // Copy rest of packet
    }
    
    // Process the data
    process_field(buffer + offset);
}

void process_field(char *field) {
    printf(field);  // Print the field
}
```
"""

EXAMPLE_OUTPUT_1 = """
{
  "summary": "Two vulnerabilities found: buffer overflow in memcpy (no bounds check on len vs buffer size) and format string vulnerability in printf.",
  "findings": [
    {
      "check_id": "BUFFER_OVERRUN",
      "severity": "critical",
      "file": "src/parser.c",
      "line": 7,
      "function_name": "process_packet",
      "title": "Heap buffer overflow in memcpy",
      "detail": "memcpy copies (len - 4) bytes into buffer[256] without checking if len exceeds 260. Attacker can control 'len' via packet data to overflow the stack buffer."
    },
    {
      "check_id": "FORMAT_STRING",
      "severity": "high",
      "file": "src/parser.c",
      "line": 14,
      "function_name": "process_field",
      "title": "Format string vulnerability in printf",
      "detail": "User-controlled 'field' pointer passed directly as format string to printf(). Attacker can use %s/%n specifiers to read/write memory."
    }
  ]
}
"""

EXAMPLE_INPUT_2 = """
```c
// File: src/alloc.c
struct Node {
    int value;
    struct Node *next;
};

struct Node* create_node(int val) {
    struct Node *node = malloc(sizeof(struct Node));
    node->value = val;  // No NULL check!
    node->next = NULL;
    return node;
}

void free_list(struct Node *head) {
    struct Node *current = head;
    while (current) {
        struct Node *next = current->next;
        free(current);
        current = next;
    }
    // Bug: head still points to freed memory
    printf("Freed list starting with value: %d\\n", head->value);
}
```
"""

EXAMPLE_OUTPUT_2 = """
{
  "summary": "Three vulnerabilities: NULL pointer dereference after malloc, use-after-free when accessing freed head, and potential format string issue.",
  "findings": [
    {
      "check_id": "NULLPTR_DEREFERENCE",
      "severity": "high",
      "file": "src/alloc.c",
      "line": 9,
      "function_name": "create_node",
      "title": "NULL dereference after malloc",
      "detail": "malloc() return value not checked before dereferencing. If allocation fails, node->value dereferences NULL pointer."
    },
    {
      "check_id": "USE_AFTER_FREE",
      "severity": "critical",
      "file": "src/alloc.c",
      "line": 22,
      "function_name": "free_list",
      "title": "Use-after-free accessing head->value",
      "detail": "After freeing all nodes in the while loop, head->value is accessed. The head pointer still points to freed memory, causing undefined behavior."
    }
  ]
}
"""

EXAMPLE_INPUT_3 = """
```c
// File: src/vuln.c
void vulnerable_copy(const char *input) {
    char small_buf[16];
    strcpy(small_buf, input);  // No bounds checking
}
```
"""

EXAMPLE_OUTPUT_3 = """
{
  "summary": "Classic stack buffer overflow via unbounded strcpy.",
  "findings": [
    {
      "check_id": "BUFFER_OVERRUN",
      "severity": "critical",
      "file": "src/vuln.c",
      "line": 4,
      "function_name": "vulnerable_copy",
      "title": "Stack buffer overflow via strcpy",
      "detail": "strcpy() copies user input into 16-byte buffer without length validation. Input longer than 15 characters will overflow the stack, enabling code execution."
    }
  ]
}
"""

# =============================================================================
# Main Prompt Template
# =============================================================================

STATIC_ANALYSIS_PROMPT = """You are RoboTrata, a security engineer specializing in C/C++ vulnerability analysis.
You analyze source code snippets from fuzz targets to identify memory-safety and security vulnerabilities.

## Your Task

Analyze the provided code snippet and identify vulnerabilities that could be triggered by fuzz testing.
Focus on issues that would cause crashes, memory corruption, or security violations detectable by sanitizers.

{vulnerability_categories}

## Output Format

You MUST respond with valid JSON matching this exact structure:

```json
{{
  "summary": "<One sentence overview of findings or 'No vulnerabilities found'>",
  "findings": [
    {{
      "check_id": "<category from table above, e.g., BUFFER_OVERRUN>",
      "severity": "<critical|high|medium|low|info>",
      "file": "<relative file path>",
      "line": <line number as integer>,
      "function_name": "<name of function containing the vulnerability>",
      "title": "<Short title, max 60 chars>",
      "detail": "<Detailed explanation: what's wrong, why it's exploitable, how to trigger>"
    }}
  ]
}}
```

## Critical Rules

1. **Valid JSON Only**: Your response must be parseable JSON. No markdown, no explanation outside JSON.
2. **Accurate Line Numbers**: Line numbers must match the actual code location.
3. **Specific Details**: The 'detail' field must explain HOW the vulnerability can be exploited.
4. **Use Standard check_ids**: Only use check_id values from the categories table above.
5. **Severity Guidelines**:
   - `critical`: RCE, arbitrary memory write, stack overflow with control
   - `high`: Memory corruption, UAF, reliable crash
   - `medium`: Null deref, bounded overflow, info leak
   - `low`: Resource leak, minor issues
   - `info`: Code smell, potential issue needing more context
6. **Max Findings**: Report at most {max_findings} most severe vulnerabilities.
7. **Empty Findings**: If no vulnerabilities found, return `{{"summary": "No vulnerabilities found in this snippet", "findings": []}}`

## Few-Shot Examples

### Example 1: Buffer overflow and format string
**Input:**
{example_input_1}

**Expected Output:**
{example_output_1}

### Example 2: NULL deref and use-after-free
**Input:**
{example_input_2}

**Expected Output:**
{example_output_2}

### Example 3: Simple buffer overflow
**Input:**
{example_input_3}

**Expected Output:**
{example_output_3}

---

## Code to Analyze

**Project:** {project}
**Fuzz Target(s):** {fuzz_target}
**File:** {file_path}

```c
{code_snippet}
```

Analyze the code above and respond with JSON only:"""


def build_static_analysis_prompt(
    project: str,
    fuzz_target: str,
    file_path: str,
    code_snippet: str,
    max_findings: int = 3,
    max_lines: int = 200,
) -> str:
    """Build the complete static analysis prompt with all examples."""
    return STATIC_ANALYSIS_PROMPT.format(
        vulnerability_categories=VULNERABILITY_CATEGORIES,
        example_input_1=EXAMPLE_INPUT_1.strip(),
        example_output_1=EXAMPLE_OUTPUT_1.strip(),
        example_input_2=EXAMPLE_INPUT_2.strip(),
        example_output_2=EXAMPLE_OUTPUT_2.strip(),
        example_input_3=EXAMPLE_INPUT_3.strip(),
        example_output_3=EXAMPLE_OUTPUT_3.strip(),
        project=project,
        fuzz_target=fuzz_target,
        file_path=file_path,
        code_snippet=code_snippet,
        max_findings=max_findings,
    )


# =============================================================================
# Function-Level Prompt (Phase 2)
# =============================================================================

FUNCTION_ANALYSIS_PROMPT = """You are RoboTrata, a security engineer specializing in C/C++ vulnerability analysis.
Analyze the provided function(s) for memory-safety and security vulnerabilities.

{vulnerability_categories}

## Output Format

You MUST respond with valid JSON matching this exact structure:

```json
{{
  "summary": "<One sentence overview of findings or 'No vulnerabilities found'>",
  "findings": [
    {{
      "check_id": "<category from table above>",
      "severity": "<critical|high|medium|low|info>",
      "file": "<relative file path>",
      "line": <line number as integer>,
      "function_name": "<name of function containing the vulnerability>",
      "title": "<Short title, max 60 chars>",
      "detail": "<Detailed explanation: what's wrong, why it's exploitable, how to trigger>"
    }}
  ]
}}
```

## Critical Rules

1. **Valid JSON Only**: Your response must be parseable JSON. No markdown, no explanation outside JSON.
2. **Accurate Line Numbers**: Use the actual line numbers shown in the code (they are from the original file).
3. **Specific Details**: The 'detail' field must explain HOW the vulnerability can be exploited.
4. **Use Standard check_ids**: Only use check_id values from the categories table above.
5. **Severity Guidelines**:
   - `critical`: RCE, arbitrary memory write, stack overflow with control
   - `high`: Memory corruption, UAF, reliable crash
   - `medium`: Null deref, bounded overflow, info leak
   - `low`: Resource leak, minor issues
   - `info`: Code smell, potential issue needing more context
6. **Max Findings**: Report at most {max_findings} most severe vulnerabilities.
7. **Empty Findings**: If no vulnerabilities, return `{{"summary": "No vulnerabilities found", "findings": []}}`

## Code to Analyze

**Project:** {project}
**File:** {file_path}
**Function(s):** {function_names}
**Lines:** {line_range}

```c
{code_snippet}
```

Analyze the function(s) above and respond with JSON only:"""


def build_function_analysis_prompt(
    project: str,
    file_path: str,
    function_names: list[str],
    line_range: str,
    code_snippet: str,
    max_findings: int = 3,
) -> str:
    """
    Build a prompt for per-function static analysis.
    
    Args:
        project: Project name
        file_path: Relative file path
        function_names: List of function names being analyzed
        line_range: Line range string (e.g., "18-47" or "18-25, 30-37, 42-47")
        code_snippet: The function body/bodies to analyze
        max_findings: Maximum findings to report
    
    Returns:
        Complete prompt string
    """
    return FUNCTION_ANALYSIS_PROMPT.format(
        vulnerability_categories=VULNERABILITY_CATEGORIES,
        project=project,
        file_path=file_path,
        function_names=", ".join(function_names),
        line_range=line_range,
        code_snippet=code_snippet,
        max_findings=max_findings,
    )


# Legacy format for backwards compatibility
STATIC_ANALYSIS_PROMPT_LEGACY = """You are RoboTrata, a security engineer helping an automated CRS.
You receive slices of a fuzz target's source code together with limited build context.
Your goal is to spot memory-safety vulnerabilities and describe how the fuzz target could exploit them.

Rules:
1. Read the snippet carefully; only rely on what you can see.
2. Focus on classic memory corruption (OOB read/write, UAF, double free), logic bugs that lead to crashes, or other fuzz-detectable findings.
3. When you spot an issue, produce a JSON object with: check_id, severity, file, line, title, detail.
4. Severity must be one of: info, low, medium, high, critical.
5. Limit yourself to at most {max_findings} findings per snippet.
6. Always return valid JSON with the shape:
   {{
     "summary": "<short overview>",
     "findings": [{{"check_id": "...", "severity": "...", "file": "...", "line": 123, "title": "...", "detail": "..."}}, ...]
   }}

Context:
- Project: {project}
- Fuzz target: {fuzz_target}
- Source file: {file_path}
- Additional notes: {notes}

Code snippet (first {max_lines} lines):
```
{code_snippet}
```
"""
