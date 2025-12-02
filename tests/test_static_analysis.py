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
        """Create a mock LangGraphClient for testing parsing."""
        from trata.src.config import RuntimeConfig
        from trata.src.tools.llm_client import LangGraphClient

        config = RuntimeConfig()
        client = LangGraphClient(config)
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
        """Create a mock LangGraphClient in offline mode."""
        from trata.src.config import RuntimeConfig
        from trata.src.tools.llm_client import LangGraphClient

        config = RuntimeConfig()
        client = LangGraphClient(config)
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
            tool="langgraph-llm",
            check_id="BUFFER_OVERRUN",
            file="src/vuln.c",
            line=42,
            severity="critical",
            title="Test",
            detail="Test detail",
        )

        assert finding.finding_id == "langgraph-llm:BUFFER_OVERRUN:src/vuln.c:42"

    def test_finding_aliases(self):
        """Test property aliases for patcher compatibility."""
        finding = StaticFinding(
            tool="langgraph-llm",
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
        from trata.src.tools.llm_client import LangGraphClient

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

        client = LangGraphClient(config)
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
        from trata.src.tools.llm_client import LangGraphClient

        # Create a long file
        long_file = temp_project / "long.c"
        long_file.write_text("\n".join([f"// Line {i}" for i in range(500)]))

        config = RuntimeConfig()
        client = LangGraphClient(config, max_lines=50)

        snippet = client._read_snippet(long_file)
        line_count = snippet.count("\n") + 1

        debug_print(f"Read {line_count} lines (max_lines=50)")

        assert line_count <= 50


# ==============================================================================
# Test End-to-End with Mocked LLM
# ==============================================================================


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
        from trata.src.tools.llm_client import LangGraphClient

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
        client = LangGraphClient(config)

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

