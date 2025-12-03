"""
Comprehensive tests for the C parser module.

Tests both tree-sitter and regex fallback parsing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add trata to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.analysis.c_parser import CParser, parse_c_file, is_tree_sitter_available
from src.analysis.data import SourceFunction, ParsedFile, SourceRange, SMALL_FUNCTION_THRESHOLD


# Debug helper
DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")

def debug_print(*args, **kwargs):
    """Print only if DEBUG is enabled."""
    if DEBUG:
        print(*args, **kwargs)


# =============================================================================
# Sample C Code for Testing
# =============================================================================

SIMPLE_C_CODE = """
#include <stdio.h>

void hello(void) {
    printf("Hello, world!\\n");
}

int main(int argc, char **argv) {
    hello();
    return 0;
}
"""

MULTI_FUNCTION_CODE = """
#include <stdlib.h>
#include <string.h>

// Small function
void tiny(void) {
    return;
}

// Another small one
int add(int a, int b) {
    return a + b;
}

// Larger function
void process_data(const char *data, size_t len) {
    if (len == 0) return;
    
    char *buffer = malloc(len + 1);
    if (!buffer) return;
    
    memcpy(buffer, data, len);
    buffer[len] = '\\0';
    
    // Do something with buffer
    printf("Data: %s\\n", buffer);
    
    free(buffer);
}

// Function returning pointer
char *create_string(const char *src) {
    if (!src) return NULL;
    char *copy = strdup(src);
    return copy;
}
"""

POINTER_RETURN_CODE = """
int *get_ptr(void) {
    static int value = 42;
    return &value;
}

struct Node *create_node(int val) {
    struct Node *n = malloc(sizeof(struct Node));
    n->value = val;
    return n;
}
"""

EMPTY_FILE_CODE = """
// This file has no functions
#include <stdio.h>

#define MAX_SIZE 100
static int global_var = 0;
"""

NESTED_BRACES_CODE = """
void complex_function(int x) {
    if (x > 0) {
        for (int i = 0; i < x; i++) {
            if (i % 2 == 0) {
                printf("even: %d\\n", i);
            } else {
                printf("odd: %d\\n", i);
            }
        }
    } else {
        printf("negative\\n");
    }
}
"""

STATIC_AND_INLINE_CODE = """
static void static_func(void) {
    printf("static\\n");
}

static inline int inline_func(int x) {
    return x * 2;
}

inline void just_inline(void) {
    // empty
}
"""


# =============================================================================
# Test: SourceRange
# =============================================================================

class TestSourceRange:
    def test_basic_range(self):
        r = SourceRange(start_byte=10, end_byte=20)
        assert r.start_byte == 10
        assert r.end_byte == 20
        assert r.length == 10
    
    def test_slice_string(self):
        source = "Hello, World!"
        r = SourceRange(7, 12)
        assert r.slice(source) == "World"
    
    def test_slice_bytes(self):
        source = b"Hello, World!"
        r = SourceRange(0, 5)
        assert r.slice(source) == b"Hello"


# =============================================================================
# Test: SourceFunction
# =============================================================================

class TestSourceFunction:
    def test_line_count(self):
        func = SourceFunction(
            name="test",
            file_path="test.c",
            start_line=10,
            end_line=20,
            signature="void test(void)",
            body="void test(void) {}",
            byte_range=SourceRange(0, 18),
        )
        assert func.line_count == 11  # 10 to 20 inclusive
    
    def test_is_small_auto_computed(self):
        # Small function (5 lines)
        small_func = SourceFunction(
            name="tiny",
            file_path="test.c",
            start_line=1,
            end_line=5,
            signature="void tiny(void)",
            body="void tiny(void) {}",
            byte_range=SourceRange(0, 10),
        )
        assert small_func.is_small is True
        debug_print(f"  Small function line_count={small_func.line_count}, threshold={SMALL_FUNCTION_THRESHOLD}")
        
        # Large function (15 lines)
        large_func = SourceFunction(
            name="big",
            file_path="test.c",
            start_line=1,
            end_line=15,
            signature="void big(void)",
            body="void big(void) { /* ... */ }",
            byte_range=SourceRange(0, 30),
        )
        assert large_func.is_small is False
        debug_print(f"  Large function line_count={large_func.line_count}")
    
    def test_finding_id_prefix(self):
        func = SourceFunction(
            name="process",
            file_path="src/vuln.c",
            start_line=10,
            end_line=20,
            signature="void process(void)",
            body="...",
            byte_range=SourceRange(0, 10),
        )
        assert func.finding_id_prefix == "src/vuln.c:process"


# =============================================================================
# Test: ParsedFile
# =============================================================================

class TestParsedFile:
    def test_get_function_by_name(self):
        func1 = SourceFunction(
            name="foo", file_path="t.c", start_line=1, end_line=5,
            signature="void foo()", body="...", byte_range=SourceRange(0, 10),
        )
        func2 = SourceFunction(
            name="bar", file_path="t.c", start_line=10, end_line=20,
            signature="void bar()", body="...", byte_range=SourceRange(20, 40),
        )
        parsed = ParsedFile(path="t.c", source="...", functions=[func1, func2])
        
        assert parsed.get_function_by_name("foo") == func1
        assert parsed.get_function_by_name("bar") == func2
        assert parsed.get_function_by_name("baz") is None
    
    def test_get_function_at_line(self):
        func1 = SourceFunction(
            name="first", file_path="t.c", start_line=5, end_line=10,
            signature="void first()", body="...", byte_range=SourceRange(0, 10),
        )
        func2 = SourceFunction(
            name="second", file_path="t.c", start_line=15, end_line=25,
            signature="void second()", body="...", byte_range=SourceRange(20, 40),
        )
        parsed = ParsedFile(path="t.c", source="...", functions=[func1, func2])
        
        assert parsed.get_function_at_line(7) == func1
        assert parsed.get_function_at_line(5) == func1
        assert parsed.get_function_at_line(10) == func1
        assert parsed.get_function_at_line(20) == func2
        assert parsed.get_function_at_line(3) is None  # Before any function
        assert parsed.get_function_at_line(12) is None  # Between functions
    
    def test_get_functions_in_range(self):
        funcs = [
            SourceFunction(
                name="a", file_path="t.c", start_line=1, end_line=5,
                signature="void a()", body="...", byte_range=SourceRange(0, 10),
            ),
            SourceFunction(
                name="b", file_path="t.c", start_line=10, end_line=15,
                signature="void b()", body="...", byte_range=SourceRange(20, 30),
            ),
            SourceFunction(
                name="c", file_path="t.c", start_line=20, end_line=25,
                signature="void c()", body="...", byte_range=SourceRange(40, 50),
            ),
        ]
        parsed = ParsedFile(path="t.c", source="...", functions=funcs)
        
        # Range covering only first function
        result = parsed.get_functions_in_range(1, 5)
        assert len(result) == 1
        assert result[0].name == "a"
        
        # Range covering first two functions
        result = parsed.get_functions_in_range(1, 12)
        assert len(result) == 2
        assert [f.name for f in result] == ["a", "b"]
        
        # Range covering all functions
        result = parsed.get_functions_in_range(1, 30)
        assert len(result) == 3
    
    def test_small_function_count(self):
        funcs = [
            SourceFunction(
                name="tiny", file_path="t.c", start_line=1, end_line=3,  # 3 lines - small
                signature="void tiny()", body="...", byte_range=SourceRange(0, 10),
            ),
            SourceFunction(
                name="big", file_path="t.c", start_line=10, end_line=30,  # 21 lines - not small
                signature="void big()", body="...", byte_range=SourceRange(20, 100),
            ),
            SourceFunction(
                name="medium", file_path="t.c", start_line=35, end_line=40,  # 6 lines - small
                signature="void medium()", body="...", byte_range=SourceRange(110, 150),
            ),
        ]
        parsed = ParsedFile(path="t.c", source="...", functions=funcs)
        
        assert parsed.function_count == 3
        assert parsed.small_function_count == 2
        debug_print(f"  Total functions: {parsed.function_count}, small: {parsed.small_function_count}")
    
    def test_get_clubbable_groups(self):
        """Test identification of small adjacent functions for clubbing."""
        funcs = [
            # Group 1: Two small adjacent functions
            SourceFunction(
                name="small1", file_path="t.c", start_line=1, end_line=5,
                signature="void small1()", body="...", byte_range=SourceRange(0, 10),
            ),
            SourceFunction(
                name="small2", file_path="t.c", start_line=7, end_line=12,  # Adjacent
                signature="void small2()", body="...", byte_range=SourceRange(15, 30),
            ),
            # Large function breaks the group
            SourceFunction(
                name="large", file_path="t.c", start_line=15, end_line=50,
                signature="void large()", body="...", byte_range=SourceRange(40, 200),
            ),
            # Group 2: Another small function (alone)
            SourceFunction(
                name="small3", file_path="t.c", start_line=55, end_line=60,
                signature="void small3()", body="...", byte_range=SourceRange(210, 240),
            ),
        ]
        parsed = ParsedFile(path="t.c", source="...", functions=funcs)
        
        groups = parsed.get_clubbable_groups()
        debug_print(f"  Clubbable groups: {[[f.name for f in g] for g in groups]}")
        
        # Should have one group with small1 and small2
        assert len(groups) == 1
        assert len(groups[0]) == 2
        assert [f.name for f in groups[0]] == ["small1", "small2"]


# =============================================================================
# Test: CParser with tree-sitter
# =============================================================================

class TestCParser:
    @pytest.fixture
    def parser(self):
        return CParser()
    
    def test_tree_sitter_available(self):
        """Verify tree-sitter is installed and working."""
        available = is_tree_sitter_available()
        debug_print(f"  tree-sitter available: {available}")
        assert available, "tree-sitter should be available for these tests"
    
    def test_parse_simple_code(self, parser):
        """Parse simple C code with two functions."""
        result = parser.parse_file("test.c", SIMPLE_C_CODE)
        
        debug_print(f"  Parsed {result.function_count} functions")
        for f in result.functions:
            debug_print(f"    - {f.name}: lines {f.start_line}-{f.end_line}")
        
        assert result.function_count == 2
        assert result.parse_errors == []
        
        # Check function names
        names = [f.name for f in result.functions]
        assert "hello" in names
        assert "main" in names
        
        # Check hello function
        hello = result.get_function_by_name("hello")
        assert hello is not None
        assert "printf" in hello.body
    
    def test_parse_multi_function_code(self, parser):
        """Parse code with multiple functions of varying sizes."""
        result = parser.parse_file("multi.c", MULTI_FUNCTION_CODE)
        
        debug_print(f"  Parsed {result.function_count} functions")
        for f in result.functions:
            debug_print(f"    - {f.name}: {f.line_count} lines, small={f.is_small}")
        
        assert result.function_count == 4
        
        # Verify function names
        names = [f.name for f in result.functions]
        assert set(names) == {"tiny", "add", "process_data", "create_string"}
        
        # Check small vs large
        tiny = result.get_function_by_name("tiny")
        add_func = result.get_function_by_name("add")
        process = result.get_function_by_name("process_data")
        
        assert tiny is not None and tiny.is_small
        assert add_func is not None and add_func.is_small
        assert process is not None and not process.is_small
    
    def test_parse_pointer_return(self, parser):
        """Parse functions that return pointers."""
        result = parser.parse_file("ptr.c", POINTER_RETURN_CODE)
        
        debug_print(f"  Parsed {result.function_count} functions")
        for f in result.functions:
            debug_print(f"    - {f.name}: signature='{f.signature}'")
        
        assert result.function_count == 2
        
        names = [f.name for f in result.functions]
        assert "get_ptr" in names
        assert "create_node" in names
    
    def test_parse_empty_file(self, parser):
        """Parse a file with no functions."""
        result = parser.parse_file("empty.c", EMPTY_FILE_CODE)
        
        debug_print(f"  Parsed {result.function_count} functions")
        
        assert result.function_count == 0
        assert result.source == EMPTY_FILE_CODE
    
    def test_parse_nested_braces(self, parser):
        """Parse function with deeply nested braces."""
        result = parser.parse_file("nested.c", NESTED_BRACES_CODE)
        
        debug_print(f"  Parsed {result.function_count} functions")
        
        assert result.function_count == 1
        func = result.functions[0]
        assert func.name == "complex_function"
        
        # Verify the entire body was captured
        assert func.body.count("{") == func.body.count("}")
        debug_print(f"    Body has {func.body.count('{')} opening braces")
    
    def test_parse_static_and_inline(self, parser):
        """Parse static and inline functions."""
        result = parser.parse_file("static.c", STATIC_AND_INLINE_CODE)
        
        debug_print(f"  Parsed {result.function_count} functions")
        for f in result.functions:
            debug_print(f"    - {f.name}: signature='{f.signature}'")
        
        assert result.function_count == 3
        
        names = [f.name for f in result.functions]
        assert "static_func" in names
        assert "inline_func" in names
        assert "just_inline" in names
    
    def test_parse_file_not_found(self, parser):
        """Handle non-existent file gracefully."""
        result = parser.parse_file("/nonexistent/path/to/file.c")
        
        assert result.function_count == 0
        assert len(result.parse_errors) > 0
        assert "not found" in result.parse_errors[0].lower()
        debug_print(f"  Error: {result.parse_errors[0]}")
    
    def test_line_numbers_accurate(self, parser):
        """Verify line numbers match actual source positions."""
        code = """
void first(void) {
    printf("first");
}

void second(void) {
    printf("second");
}
"""
        result = parser.parse_file("lines.c", code)
        
        assert result.function_count == 2
        
        first = result.get_function_by_name("first")
        second = result.get_function_by_name("second")
        
        debug_print(f"  first: lines {first.start_line}-{first.end_line}")
        debug_print(f"  second: lines {second.start_line}-{second.end_line}")
        
        # Verify first function starts at line 2 (after empty first line)
        assert first.start_line == 2
        assert first.end_line == 4
        
        # Verify second function comes after first
        assert second.start_line > first.end_line


# =============================================================================
# Test: parse_c_file convenience function
# =============================================================================

class TestParseCFileConvenience:
    def test_parse_string(self):
        """Test convenience function with string input."""
        result = parse_c_file("test.c", SIMPLE_C_CODE)
        assert result.function_count == 2
    
    def test_parse_actual_file(self, tmp_path):
        """Test parsing an actual file from disk."""
        # Create a temporary C file
        c_file = tmp_path / "test.c"
        c_file.write_text(SIMPLE_C_CODE)
        
        result = parse_c_file(c_file)
        
        assert result.function_count == 2
        assert result.path == str(c_file)


# =============================================================================
# Test: Real example-c-target files
# =============================================================================

class TestExampleCTarget:
    """Integration tests using actual example-c-target files."""
    
    @pytest.fixture
    def example_target_dir(self):
        """Path to example-c-target."""
        # Navigate from tests/ to example-c-target/
        tests_dir = Path(__file__).parent
        trata_dir = tests_dir.parent
        target_dir = trata_dir / "example-c-target"
        if not target_dir.exists():
            pytest.skip("example-c-target not found")
        return target_dir
    
    def test_parse_vuln_c(self, example_target_dir):
        """Parse the actual vuln.c file."""
        vuln_c = example_target_dir / "src" / "vuln.c"
        if not vuln_c.exists():
            pytest.skip("vuln.c not found")
        
        result = parse_c_file(vuln_c)
        
        debug_print(f"\n  Parsing: {vuln_c}")
        debug_print(f"  Found {result.function_count} functions:")
        for f in result.functions:
            debug_print(f"    - {f.name}: lines {f.start_line}-{f.end_line} ({f.line_count} lines, small={f.is_small})")
        
        # Expected functions
        expected_names = {
            "use_after_free_example",
            "null_deref_example",
            "double_free_example",
            "process_packet",
            "resize_buffer",
            "log_message",
        }
        
        actual_names = {f.name for f in result.functions}
        assert actual_names == expected_names
        
        # Check small function identification
        small_funcs = [f.name for f in result.functions if f.is_small]
        debug_print(f"  Small functions: {small_funcs}")
        
        # use_after_free_example, null_deref_example, double_free_example should be small
        assert "use_after_free_example" in small_funcs
        assert "null_deref_example" in small_funcs
        assert "double_free_example" in small_funcs
        
        # process_packet, resize_buffer, log_message should NOT be small
        assert "process_packet" not in small_funcs
        assert "resize_buffer" not in small_funcs
        assert "log_message" not in small_funcs
    
    def test_parse_main_c(self, example_target_dir):
        """Parse the actual main.c file."""
        main_c = example_target_dir / "src" / "main.c"
        if not main_c.exists():
            pytest.skip("main.c not found")
        
        result = parse_c_file(main_c)
        
        debug_print(f"\n  Parsing: {main_c}")
        debug_print(f"  Found {result.function_count} functions:")
        for f in result.functions:
            debug_print(f"    - {f.name}: lines {f.start_line}-{f.end_line}")
        
        assert result.function_count == 1
        assert result.functions[0].name == "main"
    
    def test_clubbable_groups_in_vuln_c(self, example_target_dir):
        """Test clubbable group detection on real vuln.c."""
        vuln_c = example_target_dir / "src" / "vuln.c"
        if not vuln_c.exists():
            pytest.skip("vuln.c not found")
        
        result = parse_c_file(vuln_c)
        groups = result.get_clubbable_groups()
        
        debug_print(f"\n  Clubbable groups in vuln.c:")
        for i, group in enumerate(groups):
            names = [f.name for f in group]
            total_lines = sum(f.line_count for f in group)
            debug_print(f"    Group {i+1}: {names} ({total_lines} total lines)")
        
        # The three small functions at the top should form a group
        if groups:
            first_group_names = {f.name for f in groups[0]}
            # At minimum, expect the first few small functions to be grouped
            assert len(groups[0]) >= 2


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

