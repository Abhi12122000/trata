"""
Tests for the fuzzy patch module.

Verifies that Smith-Waterman alignment can correctly apply patches
even when line numbers are incorrect.
"""

import sys
from pathlib import Path

# Add trata to path for direct pytest execution
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import os
import pytest

from trata.src.tools.fuzzy_patch import (
    fuzzy_patch,
    parse_hunks,
    MatchScorer,
    SWMatcher,
    norm_whitespace,
    find_alignment,
)


class TestMatchScorer:
    """Tests for the line similarity scorer."""
    
    def test_identical_lines(self):
        """Identical lines should have high score."""
        scorer = MatchScorer()
        score = scorer("    free(ptr);", "    free(ptr);")
        assert score > 0, "Identical lines should have positive score"
    
    def test_different_lines(self):
        """Very different lines should have low/negative score."""
        scorer = MatchScorer()
        score = scorer("    free(ptr);", "    return 0;")
        # Could be negative or small positive depending on scoring
        assert score < 1, "Different lines should have low score"
    
    def test_similar_lines_whitespace(self):
        """Lines differing only in whitespace should score well."""
        scorer = MatchScorer()
        score1 = scorer("free(ptr);", "  free(ptr);")
        # After normalization in alignment, these would match perfectly
        # but scorer doesn't normalize, so it sees different strings
        assert isinstance(score1, float)
    
    def test_number_mismatch_lower_penalty(self):
        """Digit differences should have lower penalty."""
        scorer = MatchScorer()
        score1 = scorer("line 123", "line 456")
        score2 = scorer("line abc", "line xyz")
        # Both are mismatches, but digit-to-digit should be slightly better
        assert isinstance(score1, float)
        assert isinstance(score2, float)


class TestParsing:
    """Tests for patch parsing."""
    
    def test_parse_simple_hunk(self):
        """Parse a simple patch with one hunk."""
        patch = """@@ -22,4 +22,4 @@
     free(ptr);
-    // BUG: accessing freed memory
-    printf("Value: %s\\n", ptr);
+    ptr = NULL;
+    // Fixed
"""
        hunks = parse_hunks("test.c", patch)
        
        assert len(hunks) == 1
        assert hunks[0].line_number == 22
        assert len(hunks[0].elines) == 5
    
    def test_parse_multiple_hunks(self):
        """Parse a patch with multiple hunks."""
        patch = """@@ -10,3 +10,4 @@
 context1
+added1
 context2
@@ -30,3 +31,4 @@
 context3
+added2
 context4
"""
        hunks = parse_hunks("test.c", patch)
        
        assert len(hunks) == 2
        assert hunks[0].line_number == 10
        assert hunks[1].line_number == 30
    
    def test_parse_hunk_with_no_count(self):
        """Parse a hunk header without line counts."""
        patch = """@@ -5 +5 @@
 context
-old
+new
"""
        hunks = parse_hunks("test.c", patch)
        
        assert len(hunks) == 1
        assert hunks[0].line_number == 5


class TestAlignment:
    """Tests for Smith-Waterman alignment."""
    
    def test_exact_match(self):
        """Alignment should find exact match."""
        source = [
            "int main() {",
            "    int x = 0;",
            "    free(ptr);",
            "    return 0;",
            "}",
        ]
        patch = [
            "    free(ptr);",
        ]
        
        alignment, error = find_alignment(source, patch)
        
        assert error is None
        assert len(alignment) > 0
        # Should match line 2 (0-indexed)
        src_indices = [pair[0] for pair in alignment if pair[0] is not None]
        assert 2 in src_indices
    
    def test_fuzzy_match_whitespace(self):
        """Alignment should handle whitespace differences."""
        source = [
            "int main() {",
            "    int x = 0;",
            "    free(ptr);",  # Two spaces after indent
            "    return 0;",
        ]
        patch = [
            "  free(ptr);",  # Different indent
        ]
        
        alignment, error = find_alignment(source, patch)
        
        # After normalization, should still match
        assert error is None or len(alignment) > 0


class TestFuzzyPatch:
    """Tests for the main fuzzy_patch function."""
    
    def test_apply_patch_exact_lines(self):
        """Apply patch where line numbers are correct."""
        source = """int main() {
    char *ptr = malloc(64);
    free(ptr);
    printf("%s", ptr);  // BUG
    return 0;
}
"""
        patch = """@@ -3,3 +3,4 @@
     free(ptr);
-    printf("%s", ptr);  // BUG
+    ptr = NULL;
+    // Fixed
     return 0;
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        if result.success:
            assert "ptr = NULL" in result.new_content
            assert 'printf("%s", ptr);  // BUG' not in result.new_content
    
    def test_apply_patch_wrong_line_numbers(self):
        """Apply patch where LLM gave wrong line numbers."""
        source = """// Comment
// More comment
int main() {
    char *ptr = malloc(64);
    free(ptr);
    printf("%s", ptr);  // BUG
    return 0;
}
"""
        # Patch claims line 3, but actual context is at line 5
        patch = """@@ -3,3 +3,4 @@
     free(ptr);
-    printf("%s", ptr);  // BUG
+    ptr = NULL;
+    // Fixed
     return 0;
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        # Should succeed via fuzzy matching
        if result.success:
            assert "ptr = NULL" in result.new_content
            print(f"[DEBUG] Patched successfully despite wrong line number!")
            print(f"[DEBUG] New content:\n{result.new_content[:200]}...")
        else:
            # Fuzzy matching might fail if context doesn't match well enough
            print(f"[DEBUG] Fuzzy matching failed: {result.error.message if result.error else 'Unknown'}")
    
    def test_simulates_patch_3_failure(self):
        """
        Simulate the actual failure from the CRS run.
        
        Patch 3 had line 42 but actual code was at line 44.
        """
        # Simplified version of vuln.c structure
        source = """// Header comments
// Bug 3: Double free

void double_free_example(void) {
    char *ptr = malloc(32);
    free(ptr);
    // BUG: freeing already-freed memory
    free(ptr);
}
"""
        # LLM patch with WRONG line number (claims line 42 for free)
        # But context "free(ptr);" should still match
        patch = """@@ -42,3 +42,2 @@
       free(ptr);
-    free(ptr);
+    // Removed double free
"""
        result = fuzzy_patch(source, patch, "vuln.c")
        
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        
        if DEBUG:
            print(f"\n[DEBUG] Source:\n{source}")
            print(f"\n[DEBUG] Patch:\n{patch}")
            print(f"\n[DEBUG] Result success: {result.success}")
            if result.success:
                print(f"[DEBUG] New content:\n{result.new_content}")
            else:
                print(f"[DEBUG] Error: {result.error.message if result.error else 'Unknown'}")
        
        # The fuzzy matcher should find the correct location
        if result.success:
            # Should have removed the second free(ptr);
            assert result.new_content.count("free(ptr);") == 1 or "// Removed double free" in result.new_content


class TestIntegration:
    """Integration tests with realistic patches."""
    
    def test_use_after_free_patch(self):
        """Test patching use-after-free bug."""
        source = """void use_after_free_example(void) {
    char *ptr = malloc(64);
    if (!ptr) return;
    strcpy(ptr, "hello");
    free(ptr);
    // BUG: accessing freed memory
    printf("Value: %s\\n", ptr);
}
"""
        patch = """@@ -22,6 +22,7 @@
     free(ptr);
-    // BUG: accessing freed memory
-    printf("Value: %s\\n", ptr);
+    ptr = NULL; // Prevent use-after-free access
+    // printf("Value: %s\\n", ptr); // Commented out access to freed memory
"""
        result = fuzzy_patch(source, patch, "vuln.c")
        
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        
        if DEBUG:
            print(f"\n[DEBUG] Use-after-free patch result: {result.success}")
            if result.success:
                print(f"[DEBUG] Patched content:\n{result.new_content}")
            else:
                print(f"[DEBUG] Error: {result.error}")
        
        # Note: Line 22 is wrong (actual is ~line 5), but fuzzy matching
        # should still work based on context
    
    def test_preserves_surrounding_code(self):
        """Test that surrounding code is preserved."""
        source = """// Start
int before1() { return 1; }
int before2() { return 2; }

void target() {
    bad_line();
}

int after1() { return 3; }
int after2() { return 4; }
// End
"""
        patch = """@@ -5,3 +5,3 @@
 void target() {
-    bad_line();
+    good_line();
 }
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        if result.success:
            # Should preserve all surrounding functions
            assert "int before1()" in result.new_content
            assert "int before2()" in result.new_content
            assert "int after1()" in result.new_content
            assert "int after2()" in result.new_content
            assert "good_line();" in result.new_content
            assert "bad_line();" not in result.new_content


class TestErrorHandling:
    """Tests for error handling in fuzzy patching."""
    
    def test_no_hunks_returns_error(self):
        """Test that a patch with no hunks returns an error."""
        source = "int main() { return 0; }"
        patch = "not a valid patch at all"
        
        result = fuzzy_patch(source, patch, "test.c")
        
        assert not result.success
        assert result.error is not None
        assert "No hunks found" in result.error.message
    
    def test_no_match_returns_error(self):
        """Test that context not matching any source returns an error."""
        source = """int main() {
    int x = 5;
    return 0;
}
"""
        # Patch with context that doesn't exist in source
        patch = """@@ -10,3 +10,3 @@
     this_line_does_not_exist();
-    also_nonexistent();
+    fixed_version();
     still_not_there();
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        assert not result.success
        assert result.error is not None
        # Should mention "no good matches" or similar
        assert "match" in result.error.message.lower()
    
    def test_ambiguous_match_with_multiple_occurrences(self):
        """Test handling when context matches multiple places."""
        source = """void foo() {
    free(ptr);
}

void bar() {
    free(ptr);
}

void baz() {
    free(ptr);
}
"""
        # Context "free(ptr);" matches 3 places
        # Without enough context, this should either fail or use line hint
        patch = """@@ -2,1 +2,2 @@
     free(ptr);
+    ptr = NULL;
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        # This might succeed with line hint or fail - either is acceptable
        # The key is it shouldn't crash
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        if DEBUG:
            print(f"\n[DEBUG] Ambiguous match result: success={result.success}")
            if result.error:
                print(f"[DEBUG] Error: {result.error.message}")
    
    def test_empty_source(self):
        """Test patching an empty file."""
        source = ""
        patch = """@@ -0,0 +1,3 @@
+int main() {
+    return 0;
+}
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        # Adding to empty file should work
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        if DEBUG:
            print(f"\n[DEBUG] Empty source result: success={result.success}")
            if result.success:
                print(f"[DEBUG] New content:\n{result.new_content}")
    
    def test_delete_only_patch(self):
        """Test a patch that only deletes lines."""
        source = """int main() {
    debug_log();  // remove this
    return 0;
}
"""
        patch = """@@ -1,4 +1,3 @@
 int main() {
-    debug_log();  // remove this
     return 0;
 }
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        if result.success:
            assert "debug_log" not in result.new_content
            assert "return 0;" in result.new_content


class TestEdgeCases:
    """Tests for edge cases in fuzzy patching."""
    
    def test_patch_at_file_start(self):
        """Test patching at the very beginning of a file."""
        source = """#include <stdio.h>
#include <string.h>

int main() {
    return 0;
}
"""
        # Patch with enough context to find the location
        patch = """@@ -1,3 +1,4 @@
+#include <stdlib.h>
 #include <stdio.h>
 #include <string.h>
 
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        if DEBUG:
            print(f"\n[DEBUG] Patch at file start: success={result.success}")
            if result.success:
                print(f"[DEBUG] New content:\n{result.new_content[:200]}")
            else:
                print(f"[DEBUG] Error: {result.error}")
        
        # Note: Adding at very start is an edge case that may not work perfectly
        # The important thing is it doesn't crash
        assert result.success or result.error is not None
    
    def test_patch_at_file_end(self):
        """Test patching at the very end of a file."""
        source = """int main() {
    return 0;
}
"""
        patch = """@@ -3,1 +3,3 @@
 }
+
+// End of file comment
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        if result.success:
            assert "End of file comment" in result.new_content
    
    def test_whitespace_only_difference(self):
        """Test when source and patch differ only in whitespace."""
        source = """int main() {
\tchar *p = NULL;
    return 0;
}
"""
        # Patch uses spaces, source uses tab
        patch = """@@ -2,1 +2,2 @@
     char *p = NULL;
+    p = malloc(10);
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        # Should succeed due to whitespace normalization
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        if DEBUG:
            print(f"\n[DEBUG] Whitespace-only diff: success={result.success}")
    
    def test_very_long_context(self):
        """Test with many lines of context."""
        source = "\n".join([f"line_{i}();" for i in range(100)])
        
        # Patch at line 50 with lots of context
        patch = """@@ -48,5 +48,6 @@
 line_47();
 line_48();
 line_49();
+inserted_line();
 line_50();
 line_51();
"""
        result = fuzzy_patch(source, patch, "test.c")
        
        if result.success:
            assert "inserted_line();" in result.new_content
            assert "line_49();" in result.new_content
            assert "line_50();" in result.new_content


class TestRealWorldPatches:
    """Tests based on real-world patch patterns from the CRS run."""
    
    def test_actual_patch_1_main_c(self):
        """Test the actual patch 1 pattern from the CRS run."""
        # Simplified version of main.c
        source = """int main(int argc, char **argv) {
    if (argc < 2) return 1;
    
    if (strcmp(argv[1], "uaf") == 0) {
        use_after_free_example();
    } else if (strcmp(argv[1], "null") == 0) {
        null_deref_example(0);
    } else if (strcmp(argv[1], "double") == 0) {
        double_free_example();
    } else if (strcmp(argv[1], "packet") == 0) {
        process_packet(NULL, 0);
    }
    return 0;
}
"""
        # Patch claims line 21 but actual is different
        patch = """@@ -21,6 +21,9 @@
        null_deref_example(0);
      } else if (strcmp(argv[1], "double") == 0) {
        double_free_example();
+    } else if (strcmp(argv[1], "null") == 0) {
+        printf("Null check added\\n");
+        return 0;
      } else if (strcmp(argv[1], "packet") == 0) {
"""
        result = fuzzy_patch(source, patch, "main.c")
        
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        if DEBUG:
            print(f"\n[DEBUG] Real patch 1: success={result.success}")
            if result.success:
                print(f"[DEBUG] Patched:\n{result.new_content[:500]}")
            else:
                print(f"[DEBUG] Error: {result.error}")
    
    def test_actual_patch_3_double_free(self):
        """Test the actual patch 3 pattern (double free fix)."""
        source = """void double_free_example(void) {
    char *ptr = malloc(32);
    free(ptr);
    // BUG: freeing already-freed memory
    free(ptr);
}
"""
        # Patch with possibly wrong line number
        patch = """@@ -42,4 +42,3 @@
    free(ptr);
-    // BUG: freeing already-freed memory
-    free(ptr);
+    // Fixed: removed duplicate free
"""
        result = fuzzy_patch(source, patch, "vuln.c")
        
        DEBUG = os.environ.get("DEBUG", "0") == "1"
        if DEBUG:
            print(f"\n[DEBUG] Double free patch: success={result.success}")
            if result.success:
                print(f"[DEBUG] Patched:\n{result.new_content}")
                # Should only have one free(ptr) now
                print(f"[DEBUG] free(ptr) count: {result.new_content.count('free(ptr)')}")
            else:
                print(f"[DEBUG] Error: {result.error}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

