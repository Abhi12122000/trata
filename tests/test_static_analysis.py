"""Tests for the LLM-based static analysis components."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from trata.src.prompts.static_analysis import (
    STATIC_ANALYSIS_PROMPT,
    VULNERABILITY_CATEGORIES,
    build_static_analysis_prompt,
)
from trata.src.storage.models import StaticFinding

# Debug helper
DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")


def debug_print(*args, **kwargs):
    """Print only when DEBUG mode is enabled."""
    if DEBUG:
        print(*args, **kwargs)


# ==============================================================================
# Test Prompt Building
# ==============================================================================


class TestStaticAnalysisPrompt:
    """Tests for the static analysis prompt template."""

    def test_build_prompt_includes_all_required_sections(self):
        """Ensure prompt includes all required sections."""
        prompt = build_static_analysis_prompt(
            project="test-project",
            fuzz_target="fuzz/test_fuzzer.c",
            file_path="src/vuln.c",
            code_snippet="void test() { char buf[10]; strcpy(buf, input); }",
        )
        
        debug_print(f"Prompt length: {len(prompt)}")
        
        # Check required sections
        assert "## Vulnerability Categories" in prompt
        assert "BUFFER_OVERRUN" in prompt
        assert "USE_AFTER_FREE" in prompt
        assert "NULLPTR_DEREFERENCE" in prompt
        
        # Check few-shot examples
        assert "### Example 1" in prompt
        assert "### Example 2" in prompt
        assert "### Example 3" in prompt
        
        # Check context
        assert "test-project" in prompt
        assert "fuzz/test_fuzzer.c" in prompt
        assert "src/vuln.c" in prompt
        assert "strcpy(buf, input)" in prompt

    def test_build_prompt_includes_json_format_spec(self):
        """Ensure prompt includes JSON format specification."""
        prompt = build_static_analysis_prompt(
            project="test",
            fuzz_target="test.c",
            file_path="test.c",
            code_snippet="int main() {}",
        )
        
        # Check JSON format is specified
        assert '"summary"' in prompt
        assert '"findings"' in prompt
        assert '"check_id"' in prompt
        assert '"severity"' in prompt
        assert '"line"' in prompt

    def test_build_prompt_respects_max_findings(self):
        """Ensure max_findings parameter is used."""
        prompt = build_static_analysis_prompt(
            project="test",
            fuzz_target="test.c",
            file_path="test.c",
            code_snippet="int main() {}",
            max_findings=5,
        )
        
        assert "at most 5 most severe" in prompt

    def test_vulnerability_categories_has_all_types(self):
        """Ensure all expected vulnerability categories are defined."""
        expected_categories = [
            "BUFFER_OVERRUN",
            "USE_AFTER_FREE",
            "NULLPTR_DEREFERENCE",
            "MEMORY_LEAK_C",
            "DOUBLE_FREE",
            "UNINITIALIZED_VALUE",
            "INTEGER_OVERFLOW",
            "FORMAT_STRING",
            "TYPE_CONFUSION",
            "COMMAND_INJECTION",
            "PATH_TRAVERSAL",
        ]
        
        for category in expected_categories:
            assert category in VULNERABILITY_CATEGORIES, f"Missing category: {category}"


# ==============================================================================
# Test JSON Parsing
# ==============================================================================


class TestLLMResponseParsing:
    """Tests for LLM response parsing."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock LangChainClient for testing parsing."""
        from trata.src.config import RuntimeConfig
        from trata.src.tools.llm_client import LangChainClient

        config = RuntimeConfig()
        client = LangChainClient(config)
        return client

    def test_parse_valid_json_response(self, mock_client):
        """Test parsing a well-formed JSON response."""
        response = json.dumps({
            "summary": "Found buffer overflow",
            "findings": [
                {
                    "check_id": "BUFFER_OVERRUN",
                    "severity": "critical",
                    "file": "src/vuln.c",
                    "line": 10,
                    "function_name": "process",
                    "title": "Buffer overflow in memcpy",
                    "detail": "Unbounded copy into fixed buffer",
                }
            ],
        })

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        debug_print(f"Parsed summary: {summary}")
        debug_print(f"Parsed findings: {findings}")

        assert summary == "Found buffer overflow"
        assert len(findings) == 1
        assert findings[0].check_id == "BUFFER_OVERRUN"
        assert findings[0].severity == "critical"
        assert findings[0].line == 10
        assert findings[0].function_name == "process"

    def test_parse_json_in_markdown_code_block(self, mock_client):
        """Test parsing JSON wrapped in markdown code block."""
        response = """Here's my analysis:

```json
{
  "summary": "Use after free detected",
  "findings": [
    {
      "check_id": "USE_AFTER_FREE",
      "severity": "high",
      "file": "memory.c",
      "line": 25,
      "title": "UAF vulnerability",
      "detail": "Accessing freed pointer"
    }
  ]
}
```

This is a serious vulnerability."""

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        debug_print(f"Parsed from markdown: {findings}")

        assert "Use after free" in summary
        assert len(findings) == 1
        assert findings[0].check_id == "USE_AFTER_FREE"

    def test_parse_json_without_code_block(self, mock_client):
        """Test parsing raw JSON without code block."""
        response = '{"summary": "No issues", "findings": []}'

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        assert summary == "No issues"
        assert len(findings) == 0

    def test_parse_invalid_json_returns_empty(self, mock_client):
        """Test that invalid JSON returns error summary and empty findings."""
        response = "This is not JSON at all"

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        debug_print(f"Invalid JSON result: summary={summary}, findings={findings}")

        assert "JSON parse error" in summary or len(summary) > 0
        assert len(findings) == 0

    def test_parse_validates_severity(self, mock_client):
        """Test that invalid severity values are normalized."""
        response = json.dumps({
            "summary": "Test",
            "findings": [
                {
                    "check_id": "TEST",
                    "severity": "INVALID_SEVERITY",
                    "file": "test.c",
                    "line": 1,
                    "title": "Test",
                    "detail": "Test detail",
                }
            ],
        })

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        # Invalid severity should be normalized to medium
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_parse_handles_missing_line_number(self, mock_client):
        """Test that missing line numbers default to 0."""
        response = json.dumps({
            "summary": "Test",
            "findings": [
                {
                    "check_id": "TEST",
                    "severity": "high",
                    "file": "test.c",
                    "title": "Missing line",
                    "detail": "No line specified",
                }
            ],
        })

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        assert len(findings) == 1
        assert findings[0].line == 0

    def test_parse_handles_string_line_number(self, mock_client):
        """Test that string line numbers are converted to int."""
        response = json.dumps({
            "summary": "Test",
            "findings": [
                {
                    "check_id": "TEST",
                    "severity": "high",
                    "file": "test.c",
                    "line": "42",  # String instead of int
                    "title": "String line",
                    "detail": "Line as string",
                }
            ],
        })

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        assert len(findings) == 1
        assert findings[0].line == 42

    def test_parse_uses_default_file_when_missing(self, mock_client):
        """Test that default file is used when not specified."""
        response = json.dumps({
            "summary": "Test",
            "findings": [
                {
                    "check_id": "TEST",
                    "severity": "high",
                    "line": 1,
                    "title": "No file",
                    "detail": "File not specified",
                }
            ],
        })

        summary, findings = mock_client._parse_llm_response(response, "fallback.c")

        assert len(findings) == 1
        assert findings[0].file == "fallback.c"

    def test_parse_extracts_function_name(self, mock_client):
        """Test that function_name is properly extracted."""
        response = json.dumps({
            "summary": "Test",
            "findings": [
                {
                    "check_id": "TEST",
                    "severity": "high",
                    "file": "test.c",
                    "line": 1,
                    "function_name": "vulnerable_func",
                    "title": "Test",
                    "detail": "Test",
                }
            ],
        })

        summary, findings = mock_client._parse_llm_response(response, "default.c")

        assert len(findings) == 1
        assert findings[0].function_name == "vulnerable_func"


# ==============================================================================
# Test Offline Fallback
# ==============================================================================


class TestOfflineFallback:
    """Tests for offline/heuristic fallback mode."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock LangChainClient in offline mode."""
        from trata.src.config import RuntimeConfig
        from trata.src.tools.llm_client import LangChainClient

        config = RuntimeConfig()
        client = LangChainClient(config)
        client._llm = None  # Force offline mode
        return client

    def test_offline_detects_strcpy(self, mock_client):
        """Test that offline mode detects strcpy."""
        response = mock_client._offline_response("void f() { strcpy(buf, src); }")
        payload = json.loads(response)

        debug_print(f"Offline strcpy response: {payload}")

        assert len(payload["findings"]) >= 1
        assert any(f["check_id"] == "BUFFER_OVERRUN" for f in payload["findings"])

    def test_offline_detects_free(self, mock_client):
        """Test that offline mode detects free() calls."""
        response = mock_client._offline_response("void f() { free(ptr); }")
        payload = json.loads(response)

        debug_print(f"Offline free response: {payload}")

        assert len(payload["findings"]) >= 1
        assert any(f["check_id"] == "USE_AFTER_FREE" for f in payload["findings"])

    def test_offline_detects_printf(self, mock_client):
        """Test that offline mode detects printf format strings."""
        response = mock_client._offline_response("void f() { printf(user_input); }")
        payload = json.loads(response)

        assert len(payload["findings"]) >= 1
        assert any(f["check_id"] == "FORMAT_STRING" for f in payload["findings"])

    def test_offline_limits_findings(self, mock_client):
        """Test that offline mode limits to 3 findings max."""
        code = """
        void f() {
            strcpy(a, b);
            memcpy(c, d, e);
            sprintf(f, g);
            gets(h);
            scanf("%s", i);
            free(j);
            printf(k);
            malloc(100);
        }
        """
        response = mock_client._offline_response(code)
        payload = json.loads(response)

        debug_print(f"Offline many patterns: {len(payload['findings'])} findings")

        assert len(payload["findings"]) <= 3


# ==============================================================================
# Test StaticFinding Model
# ==============================================================================


class TestStaticFindingModel:
    """Tests for the StaticFinding dataclass."""

    def test_finding_id_generation(self):
        """Test that finding_id is generated correctly."""
        finding = StaticFinding(
            tool="langchain-llm",
            check_id="BUFFER_OVERRUN",
            file="src/vuln.c",
            line=42,
            severity="critical",
            title="Test",
            detail="Test detail",
        )

        assert finding.finding_id == "langchain-llm:BUFFER_OVERRUN:src/vuln.c:42"

    def test_finding_aliases(self):
        """Test property aliases for patcher compatibility."""
        finding = StaticFinding(
            tool="langchain-llm",
            check_id="USE_AFTER_FREE",
            file="src/mem.c",
            line=100,
            severity="high",
            title="UAF",
            detail="Detailed description",
        )

        # Test aliases
        assert finding.file_path == "src/mem.c"
        assert finding.vuln_type == "USE_AFTER_FREE"
        assert finding.description == "Detailed description"


# ==============================================================================
# Integration Tests
# ==============================================================================


class TestStaticAnalysisIntegration:
    """Integration tests for the static analysis pipeline."""

    @pytest.fixture
    def temp_project(self, tmp_path):
        """Create a temporary project structure."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        # Create a vulnerable file
        (src_dir / "vuln.c").write_text("""
#include <string.h>
#include <stdlib.h>

void vulnerable(const char *input) {
    char buffer[16];
    strcpy(buffer, input);  // Buffer overflow
}

void another_vuln(void *ptr) {
    free(ptr);
    printf("%s", (char*)ptr);  // Use-after-free
}
""")

        return tmp_path

    @pytest.mark.asyncio
    async def test_file_selection_excludes_fuzz_targets(self, temp_project):
        """Test that fuzz targets are excluded from analysis."""
        from trata.src.config import RuntimeConfig, TargetProjectConfig
        from trata.src.storage.models import BuildArtifacts
        from trata.src.tools.llm_client import LangChainClient

        # Create fuzz target directory
        fuzz_dir = temp_project / "fuzz"
        fuzz_dir.mkdir()
        (fuzz_dir / "fuzzer.c").write_text("int main() {}")

        config = RuntimeConfig()
        target = TargetProjectConfig(
            name="test",
            repo_url="file://" + str(temp_project),
            local_checkout=temp_project,
            fuzz_targets=["fuzz/fuzzer.c"],
        )
        build = BuildArtifacts(
            source_dir=temp_project,
            build_dir=temp_project / "build",
        )

        client = LangChainClient(config)
        selected, skipped = client._select_candidate_files(target, build)

        debug_print(f"Selected files: {selected}")
        debug_print(f"Skipped files: {skipped}")

        # Fuzz target should be skipped
        selected_names = [f.name for f in selected]
        assert "fuzzer.c" not in selected_names

        # vuln.c should be selected
        assert "vuln.c" in selected_names

    def test_snippet_reading_respects_max_lines(self, temp_project):
        """Test that snippet reading respects max_lines limit."""
        from trata.src.config import RuntimeConfig
        from trata.src.tools.llm_client import LangChainClient

        # Create a long file
        long_file = temp_project / "long.c"
        long_file.write_text("\n".join([f"// Line {i}" for i in range(500)]))

        config = RuntimeConfig()
        client = LangChainClient(config, max_lines=50)

        snippet = client._read_snippet(long_file)
        line_count = snippet.count("\n") + 1

        debug_print(f"Read {line_count} lines (max_lines=50)")

        assert line_count <= 50


# ==============================================================================
# Test End-to-End with Mocked LLM
# ==============================================================================


class TestStaticAnalysisLimits:
    """Tests for static analysis limits."""

    def test_config_has_static_limits(self):
        """Test that RuntimeConfig has static analysis limits."""
        from trata.src.config import RuntimeConfig

        config = RuntimeConfig()

        # Check default values
        assert hasattr(config, "static_max_findings_per_file")
        assert hasattr(config, "static_max_total_findings")
        assert hasattr(config, "static_max_llm_calls")

        assert config.static_max_findings_per_file == 5
        assert config.static_max_total_findings == 50
        assert config.static_max_llm_calls == 20

    def test_client_tracks_llm_calls(self):
        """Test that LangChainClient tracks LLM calls."""
        from trata.src.config import RuntimeConfig
        from trata.src.tools.llm_client import LangChainClient

        config = RuntimeConfig()
        client = LangChainClient(config)

        assert client._llm_calls_made == 0
        assert client._max_llm_calls == 20
        assert client._total_findings == 0

    def test_client_respects_custom_limits(self):
        """Test that client uses custom limits from config."""
        from trata.src.config import RuntimeConfig
        from trata.src.tools.llm_client import LangChainClient

        config = RuntimeConfig(
            static_max_findings_per_file=3,
            static_max_total_findings=10,
            static_max_llm_calls=5,
        )
        client = LangChainClient(config)

        assert client._max_findings_per_file == 3
        assert client._max_total_findings == 10
        assert client._max_llm_calls == 5


class TestStaticAnalysisE2E:
    """End-to-end tests with mocked LLM."""

    @pytest.fixture
    def mock_llm_response(self):
        """Standard mock LLM response."""
        return json.dumps({
            "summary": "Found critical buffer overflow",
            "findings": [
                {
                    "check_id": "BUFFER_OVERRUN",
                    "severity": "critical",
                    "file": "src/vuln.c",
                    "line": 7,
                    "function_name": "vulnerable",
                    "title": "Stack buffer overflow via strcpy",
                    "detail": "strcpy() copies unbounded input into 16-byte buffer",
                }
            ],
        })

    @pytest.mark.asyncio
    async def test_full_static_review_flow(self, tmp_path, mock_llm_response):
        """Test the complete static review flow."""
        from trata.src.config import RuntimeConfig, TargetProjectConfig
        from trata.src.storage.models import BuildArtifacts, RunContext
        from trata.src.tools.llm_client import LangChainClient

        # Setup project
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "vuln.c").write_text("""
void vulnerable(const char *input) {
    char buffer[16];
    strcpy(buffer, input);
}
""")

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()

        config = RuntimeConfig()
        target = TargetProjectConfig(
            name="test-project",
            repo_url="file://" + str(src_dir),
            local_checkout=src_dir,
        )
        build = BuildArtifacts(
            source_dir=src_dir,
            build_dir=tmp_path / "build",
        )
        run_ctx = RunContext(
            project="test-project",
            run_id="test-run",
            root=tmp_path,
            logs_dir=logs_dir,
            artifacts_dir=artifacts_dir,
        )

        # Create client with mocked LLM
        client = LangChainClient(config)

        with patch.object(client, "_invoke_llm", new_callable=AsyncMock) as mock_invoke:
            mock_invoke.return_value = mock_llm_response

            summary, findings = await client.run_static_review(
                target=target,
                build=build,
                run_ctx=run_ctx,
            )

            debug_print(f"E2E Summary: {summary}")
            debug_print(f"E2E Findings: {findings}")

            # Verify results
            assert len(findings) >= 1
            assert any(f.check_id == "BUFFER_OVERRUN" for f in findings)

            # Verify logs were created
            assert (logs_dir / "llm_summary.json").exists()


# ==============================================================================
# Phase 2: Function-Level Analysis Tests
# ==============================================================================


class TestFunctionLevelPrompt:
    """Tests for the function-level analysis prompt."""
    
    def test_build_function_prompt_includes_function_context(self):
        """Verify function prompt includes function-specific context."""
        from trata.src.prompts.static_analysis import build_function_analysis_prompt
        
        prompt = build_function_analysis_prompt(
            project="test-project",
            file_path="src/vuln.c",
            function_names=["process_packet"],
            line_range="55-82",
            code_snippet="void process_packet(const uint8_t *data, size_t size) { }",
            max_findings=3,
        )
        
        debug_print(f"Function prompt length: {len(prompt)}")
        
        # Check function-specific context
        assert "process_packet" in prompt
        assert "55-82" in prompt
        assert "src/vuln.c" in prompt
        assert "test-project" in prompt
        
        # Check JSON format spec
        assert '"check_id"' in prompt
        assert '"severity"' in prompt
        assert '"line"' in prompt
    
    def test_build_function_prompt_handles_multiple_functions(self):
        """Verify prompt handles clubbed functions."""
        from trata.src.prompts.static_analysis import build_function_analysis_prompt
        
        prompt = build_function_analysis_prompt(
            project="test-project",
            file_path="src/vuln.c",
            function_names=["func1", "func2", "func3"],
            line_range="10-20, 25-30, 35-40",
            code_snippet="void func1() {}\nvoid func2() {}\nvoid func3() {}",
            max_findings=5,
        )
        
        # All function names should be mentioned
        assert "func1" in prompt
        assert "func2" in prompt
        assert "func3" in prompt
        assert "10-20, 25-30, 35-40" in prompt


class TestFunctionClubbing:
    """Tests for function clubbing logic."""
    
    @pytest.fixture
    def multi_function_source(self, tmp_path):
        """Create a source file with multiple functions of varying sizes."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        
        # Create file with mix of small and large functions
        code = """
// Small function 1 (5 lines)
void small1(void) {
    int x = 1;
    x++;
}

// Small function 2 (4 lines)
void small2(void) {
    return;
}

// Large function (20 lines)
void large_func(int x) {
    int a = 1;
    int b = 2;
    int c = 3;
    if (x > 0) {
        a = x;
        b = x * 2;
        c = x * 3;
    } else {
        a = -x;
        b = -x * 2;
        c = -x * 3;
    }
    printf("%d %d %d", a, b, c);
    for (int i = 0; i < x; i++) {
        printf("%d", i);
    }
}

// Small function 3 (3 lines)
void small3(void) {
    return;
}
"""
        (src_dir / "mixed.c").write_text(code)
        return src_dir
    
    def test_clubbing_groups_small_adjacent_functions(self, multi_function_source, tmp_path):
        """Verify small adjacent functions are clubbed together."""
        from trata.src.analysis.c_parser import parse_c_file
        
        parsed = parse_c_file(multi_function_source / "mixed.c")
        
        debug_print(f"Parsed {parsed.function_count} functions:")
        for f in parsed.functions:
            debug_print(f"  - {f.name}: lines {f.start_line}-{f.end_line}, small={f.is_small}")
        
        groups = parsed.get_clubbable_groups()
        
        debug_print(f"Clubbable groups: {[[f.name for f in g] for g in groups]}")
        
        # small1 and small2 should be clubbed (adjacent)
        # large_func breaks the chain
        # small3 is alone after large_func
        assert len(groups) >= 1
        
        # First group should contain small1 and small2
        first_group_names = [f.name for f in groups[0]]
        assert "small1" in first_group_names
        assert "small2" in first_group_names
        assert "large_func" not in first_group_names
    
    def test_build_analysis_units_creates_correct_structure(self, multi_function_source, tmp_path):
        """Verify _build_analysis_units creates correct unit structure."""
        import asyncio
        from trata.src.config import RuntimeConfig, TargetProjectConfig
        from trata.src.storage.models import BuildArtifacts, RunContext
        from trata.src.tools.llm_client import LangChainClient
        
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        
        config = RuntimeConfig()
        client = LangChainClient(config)
        
        # Parse files
        parsed_files = client._parse_candidate_files(
            [multi_function_source / "mixed.c"],
            multi_function_source,
            RunContext(
                project="test",
                run_id="test",
                root=tmp_path,
                logs_dir=logs_dir,
                artifacts_dir=artifacts_dir,
            ),
            None,
        )
        
        # Build analysis units
        units = client._build_analysis_units(
            parsed_files,
            multi_function_source,
            RunContext(
                project="test",
                run_id="test",
                root=tmp_path,
                logs_dir=logs_dir,
                artifacts_dir=artifacts_dir,
            ),
            None,
        )
        
        debug_print(f"Analysis units: {len(units)}")
        for u in units:
            debug_print(f"  - {u['relative_file']}: {u['function_names']} (clubbed={u['is_clubbed']})")
        
        # Verify structure
        assert len(units) > 0
        
        for unit in units:
            assert "file_path" in unit
            assert "relative_file" in unit
            assert "function_names" in unit
            assert "line_range" in unit
            assert "code" in unit
            assert "is_clubbed" in unit
            
            # Code should not be empty
            assert len(unit["code"]) > 0
            
            # Function names should match what's in code
            for func_name in unit["function_names"]:
                if func_name != "<file-level>":
                    assert func_name in unit["code"]


class TestFunctionLevelE2E:
    """End-to-end tests for function-level static analysis."""
    
    @pytest.mark.asyncio
    async def test_function_level_analysis_calls_llm_per_function(self, tmp_path):
        """Verify LLM is called per function (or clubbed group)."""
        from unittest.mock import AsyncMock, patch
        from trata.src.config import RuntimeConfig, TargetProjectConfig
        from trata.src.storage.models import BuildArtifacts, RunContext
        from trata.src.tools.llm_client import LangChainClient
        
        # Create source with 2 large functions
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "test.c").write_text("""
void large_func1(int x) {
    int a = 1;
    int b = 2;
    int c = 3;
    if (x > 0) {
        a = x;
        b = x * 2;
        c = x * 3;
        printf("%d", a);
        printf("%d", b);
        printf("%d", c);
    }
}

void large_func2(int y) {
    int d = 1;
    int e = 2;
    int f = 3;
    if (y > 0) {
        d = y;
        e = y * 2;
        f = y * 3;
        printf("%d", d);
        printf("%d", e);
        printf("%d", f);
    }
}
""")
        
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        
        config = RuntimeConfig()
        target = TargetProjectConfig(
            name="test",
            repo_url="file://" + str(src_dir),
            local_checkout=src_dir,
        )
        build = BuildArtifacts(source_dir=src_dir, build_dir=tmp_path / "build")
        run_ctx = RunContext(
            project="test",
            run_id="test",
            root=tmp_path,
            logs_dir=logs_dir,
            artifacts_dir=artifacts_dir,
        )
        
        client = LangChainClient(config)
        
        call_count = 0
        analyzed_functions = []
        
        async def mock_invoke(prompt):
            nonlocal call_count
            call_count += 1
            
            # Track which functions were analyzed
            if "large_func1" in prompt:
                analyzed_functions.append("large_func1")
            if "large_func2" in prompt:
                analyzed_functions.append("large_func2")
            
            return '{"summary": "No vulnerabilities found", "findings": []}'
        
        with patch.object(client, "_invoke_llm", side_effect=mock_invoke):
            summary, findings = await client.run_static_review(target, build, run_ctx)
        
        debug_print(f"LLM call count: {call_count}")
        debug_print(f"Analyzed functions: {analyzed_functions}")
        
        # Each large function should be analyzed separately
        assert call_count == 2, f"Expected 2 LLM calls (one per function), got {call_count}"
        assert "large_func1" in analyzed_functions
        assert "large_func2" in analyzed_functions
    
    @pytest.mark.asyncio
    async def test_clubbed_functions_analyzed_together(self, tmp_path):
        """Verify small adjacent functions are analyzed in one LLM call."""
        from unittest.mock import AsyncMock, patch
        from trata.src.config import RuntimeConfig, TargetProjectConfig
        from trata.src.storage.models import BuildArtifacts, RunContext
        from trata.src.tools.llm_client import LangChainClient
        
        # Create source with 3 small adjacent functions
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "small.c").write_text("""
void tiny1(void) {
    return;
}

void tiny2(void) {
    return;
}

void tiny3(void) {
    return;
}
""")
        
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        
        config = RuntimeConfig()
        target = TargetProjectConfig(
            name="test",
            repo_url="file://" + str(src_dir),
            local_checkout=src_dir,
        )
        build = BuildArtifacts(source_dir=src_dir, build_dir=tmp_path / "build")
        run_ctx = RunContext(
            project="test",
            run_id="test",
            root=tmp_path,
            logs_dir=logs_dir,
            artifacts_dir=artifacts_dir,
        )
        
        client = LangChainClient(config)
        
        call_count = 0
        prompts_received = []
        
        async def mock_invoke(prompt):
            nonlocal call_count
            call_count += 1
            prompts_received.append(prompt)
            return '{"summary": "No vulnerabilities found", "findings": []}'
        
        with patch.object(client, "_invoke_llm", side_effect=mock_invoke):
            summary, findings = await client.run_static_review(target, build, run_ctx)
        
        debug_print(f"LLM call count: {call_count}")
        
        # All 3 small functions should be clubbed into 1 call
        assert call_count == 1, f"Expected 1 LLM call (clubbed), got {call_count}"
        
        # The single prompt should contain all 3 functions
        prompt = prompts_received[0]
        assert "tiny1" in prompt
        assert "tiny2" in prompt
        assert "tiny3" in prompt

