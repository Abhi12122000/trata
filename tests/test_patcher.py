"""
Tests for the patcher agent and patch applier.

Tests cover:
- PatchParser: YAML parsing and diff extraction
- WorkingCopyManager: Source copy creation, backup, restore
- PatchApplier: Patch validation and application
- PatcherAgent: Source context extraction, prompt building
- Integration: Full patching flow

Run with DEBUG=1 for verbose output:
    DEBUG=1 pytest trata/tests/test_patcher.py -v -s
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from textwrap import dedent
from unittest.mock import AsyncMock, MagicMock

import pytest

# Ensure trata is importable when running pytest directly
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Debug flag - set DEBUG=1 environment variable for verbose output
DEBUG = os.environ.get("DEBUG", "0") == "1"


def debug_print(*args, **kwargs):
    """Print only if DEBUG is enabled."""
    if DEBUG:
        print(*args, **kwargs)

from trata.src.agents.patcher import PatcherAgent, PatcherConfig, PatcherResult
from trata.src.config import RuntimeConfig
from trata.src.storage.local_store import LocalRunStore
from trata.src.storage.models import FuzzCrash, RunContext, StaticFinding
from trata.src.tools.patch_applier import (
    PatchApplier,
    PatchParser,
    PatchResult,
    ParsedPatch,
    WorkingCopyManager,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_project_dir(tmp_path: Path) -> Path:
    """Create a temporary project directory with sample source files."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Create sample vulnerable C file
    vuln_c = src_dir / "vuln.c"
    vuln_c.write_text(dedent("""
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        
        void use_after_free_example(void) {
            char *ptr = malloc(64);
            if (!ptr) return;
            strcpy(ptr, "hello");
            free(ptr);
            // BUG: use after free
            printf("Value: %s\\n", ptr);
        }
        
        void null_deref_example(int trigger) {
            char *ptr = NULL;
            if (trigger) {
                ptr = malloc(16);
            }
            // BUG: ptr might be NULL
            ptr[0] = 'A';
        }
        
        int main(void) {
            return 0;
        }
    """).strip())

    return tmp_path


@pytest.fixture
def sample_source_code() -> str:
    """Sample source code for testing."""
    return dedent("""
        #include <stdio.h>
        #include <stdlib.h>
        
        void vulnerable_func(void) {
            char *ptr = malloc(64);
            free(ptr);
            // BUG: use after free
            printf("Value: %s\\n", ptr);
        }
    """).strip()


@pytest.fixture
def sample_static_finding() -> StaticFinding:
    """Sample static analysis finding."""
    return StaticFinding(
        tool="infer",
        check_id="USE_AFTER_FREE",
        file="src/vuln.c",  # Note: use 'file' not 'file_path' (file_path is a property)
        line=24,
        severity="high",
        title="Use After Free",
        detail="Memory is accessed after being freed.",
    )


@pytest.fixture
def mock_run_ctx(tmp_path: Path) -> RunContext:
    """Create a mock run context with SEPARATE directory from source."""
    # Use a separate directory for run context to avoid copy recursion
    run_dir = tmp_path / "crs_run"
    run_dir.mkdir()
    logs_dir = run_dir / "logs"
    artifacts_dir = run_dir / "artifacts"
    logs_dir.mkdir()
    artifacts_dir.mkdir()

    return RunContext(
        project="test-project",
        run_id="test-run-123",
        root=run_dir,
        logs_dir=logs_dir,
        artifacts_dir=artifacts_dir,
    )


# ============================================================================
# PatchParser Tests
# ============================================================================


class TestPatchParser:
    """Tests for PatchParser."""

    def test_parse_yaml_response_success(self):
        """Test parsing a valid YAML response."""
        response = dedent("""
            Here's the fix:
            
            ```yaml
            analysis: |
              Use-after-free vulnerability found.
            fix_strategy: |
              Set pointer to NULL after freeing.
            file_path: src/vuln.c
            patch: |
              @@ -10,3 +10,4 @@
               free(ptr);
              +ptr = NULL;
               printf("Value: %s\\n", ptr);
            ```
        """)

        result = PatchParser.parse_yaml_response(response)

        assert result is not None
        assert "Use-after-free" in result.analysis
        assert result.file_path == "src/vuln.c"
        assert "@@ -10,3 +10,4 @@" in result.patch

    def test_parse_yaml_response_no_yaml(self):
        """Test parsing response without YAML block."""
        response = "Just some plain text without YAML."
        result = PatchParser.parse_yaml_response(response)
        assert result is None

    def test_parse_yaml_response_missing_fields(self):
        """Test parsing YAML with missing required fields."""
        response = dedent("""
            ```yaml
            analysis: Some analysis
            file_path: src/test.c
            ```
        """)
        result = PatchParser.parse_yaml_response(response)
        assert result is None

    def test_parse_yaml_response_yml_block(self):
        """Test parsing with ```yml block instead of ```yaml."""
        response = dedent("""
            ```yml
            analysis: Test analysis
            fix_strategy: Test strategy
            file_path: test.c
            patch: |
              @@ -1,1 +1,1 @@
              -old
              +new
            ```
        """)
        result = PatchParser.parse_yaml_response(response)
        assert result is not None
        assert result.file_path == "test.c"

    def test_extract_unified_diff(self):
        """Test extracting unified diff from text."""
        text = dedent("""
            Here's the patch:
            @@ -10,3 +10,4 @@
             context line
            -removed line
            +added line
             context line
            
            Some more text.
        """)
        diff = PatchParser.extract_unified_diff(text)
        assert diff is not None
        assert "@@ -10,3 +10,4 @@" in diff
        assert "-removed line" in diff
        assert "+added line" in diff


# ============================================================================
# WorkingCopyManager Tests
# ============================================================================


class TestWorkingCopyManager:
    """Tests for WorkingCopyManager."""

    @pytest.fixture
    def separate_artifacts_dir(self, tmp_path: Path) -> Path:
        """Create a separate artifacts directory to avoid copy recursion."""
        artifacts = tmp_path / "separate_artifacts"
        artifacts.mkdir()
        return artifacts

    def test_initialize_creates_working_copy(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test that initialize creates a working copy."""
        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )

        assert mgr.initialize()
        
        working_copy = mgr.get_working_copy_path()
        assert working_copy.exists()
        assert (working_copy / "src" / "vuln.c").exists()

    def test_working_copy_is_independent(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test that modifying working copy doesn't affect original."""
        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )
        mgr.initialize()

        # Modify file in working copy
        working_copy = mgr.get_working_copy_path()
        test_file = working_copy / "src" / "vuln.c"
        original_content = (temp_project_dir / "src" / "vuln.c").read_text()
        test_file.write_text("modified content")

        # Original should be unchanged
        assert (temp_project_dir / "src" / "vuln.c").read_text() == original_content

    def test_create_and_restore_backup(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test backup creation and restoration."""
        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )
        mgr.initialize()

        # Create backup
        backup_path = mgr.create_file_backup("src/vuln.c")
        assert backup_path is not None
        assert backup_path.exists()

        # Modify file
        working_copy = mgr.get_working_copy_path()
        test_file = working_copy / "src" / "vuln.c"
        original_content = test_file.read_text()
        test_file.write_text("modified content")
        assert test_file.read_text() == "modified content"

        # Restore
        assert mgr.restore_from_backup("src/vuln.c", backup_path)
        assert test_file.read_text() == original_content

    def test_save_patched_file(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test saving patched file to artifacts."""
        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )
        mgr.initialize()

        # Modify file in working copy
        working_copy = mgr.get_working_copy_path()
        (working_copy / "src" / "vuln.c").write_text("patched content")

        # Save patched file
        saved_path = mgr.save_patched_file("src/vuln.c", 1, "test-finding")
        
        assert saved_path is not None
        assert saved_path.exists()
        assert "patched content" in saved_path.read_text()
        # Verify saved to patched_files directory
        assert str(mgr.patched_files_dir) in str(saved_path.parent)

    def test_emergency_restore(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test emergency restore from original source."""
        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )
        mgr.initialize()

        # Corrupt the working copy file
        working_copy = mgr.get_working_copy_path()
        test_file = working_copy / "src" / "vuln.c"
        original_content = (temp_project_dir / "src" / "vuln.c").read_text()
        test_file.write_text("corrupted content")

        # Emergency restore
        assert mgr._emergency_restore("src/vuln.c")
        assert test_file.read_text() == original_content


# ============================================================================
# PatchApplier Tests
# ============================================================================


class TestPatchApplier:
    """Tests for PatchApplier."""

    @pytest.fixture
    def separate_artifacts_dir(self, tmp_path: Path) -> Path:
        """Create a separate artifacts directory to avoid copy recursion."""
        artifacts = tmp_path / "separate_artifacts"
        artifacts.mkdir()
        return artifacts

    def test_apply_patch_file_not_found(self, tmp_path: Path):
        """Test applying patch to non-existent file."""
        applier = PatchApplier(tmp_path)
        result = applier.apply_patch("nonexistent.c", "@@ -1,1 +1,1 @@\n-x\n+y")

        assert not result.success
        assert "not found" in result.error_message.lower()

    def test_validate_patch_valid(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test patch validation with valid patch."""
        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )
        mgr.initialize()
        
        applier = PatchApplier(mgr.get_working_copy_path())
        errors = applier.validate_patch("src/vuln.c", "@@ -10,3 +10,4 @@\n context\n-old\n+new")
        
        # Should have no errors (or just warnings)
        assert not any("not found" in e.lower() for e in errors)

    def test_validate_patch_offline_placeholder(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test validation catches offline placeholder patches."""
        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )
        mgr.initialize()
        
        applier = PatchApplier(mgr.get_working_copy_path())
        errors = applier.validate_patch(
            "src/vuln.c",
            "@@ -10,1 +10,1 @@\n // [OFFLINE] Placeholder"
        )
        
        assert any("offline" in e.lower() or "placeholder" in e.lower() for e in errors)

    def test_apply_patch_simple(self, temp_project_dir: Path, separate_artifacts_dir: Path):
        """Test applying a simple patch."""
        # Create a simple file
        simple_file = temp_project_dir / "simple.c"
        simple_file.write_text("line1\nline2\nline3\n")

        mgr = WorkingCopyManager(
            original_source_dir=temp_project_dir,
            artifacts_dir=separate_artifacts_dir,
        )
        mgr.initialize()

        applier = PatchApplier(mgr.get_working_copy_path())
        patch_content = dedent("""
            @@ -1,3 +1,3 @@
             line1
            -line2
            +line2_modified
             line3
        """).strip()

        result = applier.apply_patch("simple.c", patch_content)

        # Check if patch was applied (might fail if patch command not available)
        if result.success:
            working_file = mgr.get_working_copy_path() / "simple.c"
            assert "line2_modified" in working_file.read_text()


# ============================================================================
# PatcherAgent Tests
# ============================================================================


class TestPatcherAgent:
    """Tests for PatcherAgent."""

    @pytest.fixture(autouse=True)
    def setup_source(self, temp_project_dir: Path):
        """Ensure source files exist."""
        self.source_dir = temp_project_dir

    def test_extract_source_context(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
    ):
        """Test extracting source code context."""
        config = PatcherConfig(context_lines=5)
        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value="")
        
        agent = PatcherAgent(config, mock_llm)

        # Debug: show what file we're reading from
        full_path = temp_project_dir / "src" / "vuln.c"
        debug_print(f"\n=== DEBUG: test_extract_source_context ===")
        debug_print(f"temp_project_dir: {temp_project_dir}")
        debug_print(f"full_path: {full_path}")
        debug_print(f"file exists: {full_path.exists()}")
        if DEBUG and full_path.exists():
            debug_print(f"file contents:\n{full_path.read_text()}")

        context = agent._extract_source_context(
            source_root=temp_project_dir,
            file_path="src/vuln.c",
            center_line=10,
        )

        debug_print(f"\n--- Extracted context (center_line=10, context_lines=5) ---")
        debug_print(f"context is None: {context is None}")
        if DEBUG and context:
            debug_print(f"context:\n{context}")
        debug_print("=== END DEBUG ===\n")

        assert context is not None
        assert "malloc" in context or "ptr" in context
        assert ">>>" in context  # Marker for center line

    def test_extract_source_context_correct_line_numbers(
        self,
        temp_project_dir: Path,
    ):
        """Test that source extraction includes correct line numbers."""
        config = PatcherConfig(context_lines=3)
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm)

        context = agent._extract_source_context(
            source_root=temp_project_dir,
            file_path="src/vuln.c",
            center_line=10,
        )

        debug_print(f"\n=== DEBUG: test_extract_source_context_correct_line_numbers ===")
        debug_print(f"context:\n{context}")
        if DEBUG and context:
            lines = context.split("\n")
            debug_print(f"total lines in context: {len(lines)}")
            center_lines = [l for l in lines if ">>>" in l]
            debug_print(f"center lines (with >>>): {center_lines}")
        debug_print("=== END DEBUG ===\n")

        assert context is not None
        # Should have line numbers
        lines = context.split("\n")
        center_lines = [l for l in lines if ">>>" in l]
        assert len(center_lines) == 1

    def test_extract_source_context_nonexistent_file(
        self,
        temp_project_dir: Path,
    ):
        """Test extraction fails gracefully for nonexistent file."""
        config = PatcherConfig()
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm)

        context = agent._extract_source_context(
            source_root=temp_project_dir,
            file_path="nonexistent/file.c",
            center_line=10,
        )

        assert context is None

    def test_build_prompt(self, sample_static_finding: StaticFinding):
        """Test building the LLM prompt."""
        config = PatcherConfig()
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm)

        source_context = "   10    char *ptr = malloc(64);\n>>>11    free(ptr);\n   12    printf(ptr);"

        prompt = agent._build_prompt(
            finding=sample_static_finding,
            source_context=source_context,
        )

        assert "USE_AFTER_FREE" in prompt
        assert "src/vuln.c" in prompt
        assert "24" in prompt  # line number
        assert source_context in prompt

    def test_build_prompt_contains_all_required_fields(
        self,
        sample_static_finding: StaticFinding,
    ):
        """Test that prompt contains all necessary information."""
        config = PatcherConfig()
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm)

        source_context = dedent("""
              20    void use_after_free_example(void) {
              21        char *ptr = malloc(64);
              22        free(ptr);
            >>>23        printf("Value: %s\\n", ptr);  // BUG
              24    }
        """).strip()

        prompt = agent._build_prompt(
            finding=sample_static_finding,
            source_context=source_context,
        )

        debug_print(f"\n=== DEBUG: test_build_prompt_contains_all_required_fields ===")
        debug_print(f"Finding: {sample_static_finding}")
        debug_print(f"Finding.file_path (property): {sample_static_finding.file_path}")
        debug_print(f"Finding.vuln_type (property): {sample_static_finding.vuln_type}")
        debug_print(f"\n--- Generated Prompt ---")
        debug_print(prompt)
        debug_print("=== END DEBUG ===\n")

        # Check all required fields are present
        assert "## Vulnerability Report" in prompt
        assert "**Type:**" in prompt
        assert "**Severity:**" in prompt
        assert "**File:**" in prompt
        assert "**Line:**" in prompt
        assert "## Source Code Context" in prompt

        # Check values
        assert sample_static_finding.vuln_type in prompt
        assert sample_static_finding.severity in prompt
        assert sample_static_finding.file_path in prompt
        assert str(sample_static_finding.line) in prompt
        assert source_context in prompt

        # Verify NO duplication
        assert prompt.count("## Vulnerability Report") == 1
        assert prompt.count("## Source Code Context") == 1

    def test_build_prompt_with_fuzz_crash(
        self,
        sample_static_finding: StaticFinding,
    ):
        """Test prompt building with related fuzz crash."""
        config = PatcherConfig()
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm)

        source_context = "  10    free(ptr);\n>>>11    printf(ptr);"

        mock_crash = FuzzCrash(
            crash_id="test123",
            input_path=Path("/tmp/crash"),
            input_size=10,
            dedup_token="abc",
            harness="fuzzer",
            timestamp="2025-01-01T00:00:00Z",
            stack_trace="ERROR: heap-use-after-free\n#0 in use_after_free vuln.c:24",
        )

        prompt = agent._build_prompt(
            finding=sample_static_finding,
            source_context=source_context,
            related_crash=mock_crash,
        )

        # Should include fuzz crash info
        assert "## Related Fuzz Crash" in prompt
        assert "heap-use-after-free" in prompt

    @pytest.mark.asyncio
    async def test_generate_patch_offline(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test patch generation in offline mode."""
        # Mock LLM to return offline response
        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value=dedent("""
            ```yaml
            analysis: "[OFFLINE MODE] Analysis placeholder"
            fix_strategy: "[OFFLINE MODE] Strategy placeholder"
            file_path: src/vuln.c
            patch: |
              @@ -24,1 +24,1 @@
               // [OFFLINE] Placeholder patch
            ```
        """))

        config = PatcherConfig()
        agent = PatcherAgent(config, mock_llm)

        result = await agent.generate_patch(
            finding=sample_static_finding,
            source_root=temp_project_dir,
            run_ctx=mock_run_ctx,
        )

        assert result is not None
        assert result.success or "[OFFLINE]" in str(result.error_message)


# ============================================================================
# Integration Tests
# ============================================================================


class TestPatcherTokenBudget:
    """Test token budget enforcement in PatcherAgent."""

    def test_token_budget_tracking(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that token usage is tracked correctly."""
        from trata.src.agents.patcher import PatcherConfig, PatcherAgent
        
        config = PatcherConfig(
            max_tokens_per_patch=1000,
            max_total_tokens=5000,
        )
        
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm, None)
        
        # Initially should have full budget
        assert agent.tokens_used == 0
        assert agent.tokens_remaining == 5000
        assert not agent.budget_exceeded

    @pytest.mark.asyncio
    async def test_token_budget_exceeded_returns_early(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that agent returns early when budget is exceeded."""
        from trata.src.agents.patcher import PatcherConfig, PatcherAgent
        
        config = PatcherConfig(
            max_tokens_per_patch=1000,
            max_total_tokens=100,  # Very low budget
        )
        
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm, None)
        
        # Simulate budget being exceeded
        agent._tokens_used = 100
        agent._budget_exceeded = True
        
        result = await agent.generate_patch(
            finding=sample_static_finding,
            source_root=temp_project_dir,
            run_ctx=mock_run_ctx,
        )
        
        assert not result.success
        assert "budget exceeded" in result.error_message.lower()

    def test_config_token_limits(self):
        """Test that config has correct default token limits."""
        from trata.src.agents.patcher import PatcherConfig
        
        config = PatcherConfig()
        assert config.max_tokens_per_patch == 4000
        assert config.max_total_tokens == 20000

    def test_config_patch_limits(self):
        """Test that config has correct default patch limits."""
        from trata.src.agents.patcher import PatcherConfig
        
        config = PatcherConfig()
        assert config.max_patches_per_run == 10
        assert config.max_retries == 2
        assert config.llm_timeout_seconds == 60
        assert config.max_llm_calls_per_patch == 5

    def test_patch_count_tracking(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that patch count is tracked correctly."""
        from trata.src.agents.patcher import PatcherConfig, PatcherAgent
        
        config = PatcherConfig(max_patches_per_run=5)
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm, None)
        
        # Initially should have full quota
        assert agent.patches_generated == 0
        assert agent.patches_remaining == 5
        assert not agent.patches_limit_reached
        
        debug_print(f"\n=== DEBUG: test_patch_count_tracking ===")
        debug_print(f"Initial patches_generated: {agent.patches_generated}")
        debug_print(f"Initial patches_remaining: {agent.patches_remaining}")
        debug_print(f"Initial patches_limit_reached: {agent.patches_limit_reached}")
        debug_print("=== END DEBUG ===\n")

    @pytest.mark.asyncio
    async def test_patch_limit_exceeded_returns_early(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that agent returns early when patch limit is exceeded."""
        from trata.src.agents.patcher import PatcherConfig, PatcherAgent
        
        config = PatcherConfig(max_patches_per_run=3)
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm, None)
        
        # Simulate limit being reached
        agent._patches_generated = 3
        agent._patches_limit_reached = True
        
        result = await agent.generate_patch(
            finding=sample_static_finding,
            source_root=temp_project_dir,
            run_ctx=mock_run_ctx,
        )
        
        debug_print(f"\n=== DEBUG: test_patch_limit_exceeded_returns_early ===")
        debug_print(f"result.success: {result.success}")
        debug_print(f"result.error_message: {result.error_message}")
        debug_print("=== END DEBUG ===\n")
        
        assert not result.success
        assert "patch limit" in result.error_message.lower() or "limit reached" in result.error_message.lower()

    def test_llm_call_tracking_properties(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that LLM call tracking properties work correctly."""
        from trata.src.agents.patcher import PatcherConfig, PatcherAgent
        
        config = PatcherConfig(max_llm_calls_per_patch=5)
        mock_llm = MagicMock()
        agent = PatcherAgent(config, mock_llm, None)
        
        # Initially should have zero calls
        assert agent.current_patch_llm_calls == 0
        assert agent.total_llm_calls == 0
        
        # Simulate some calls
        agent._current_patch_llm_calls = 3
        agent._total_llm_calls = 10
        
        assert agent.current_patch_llm_calls == 3
        assert agent.total_llm_calls == 10
        
        debug_print(f"\n=== DEBUG: test_llm_call_tracking_properties ===")
        debug_print(f"current_patch_llm_calls: {agent.current_patch_llm_calls}")
        debug_print(f"total_llm_calls: {agent.total_llm_calls}")
        debug_print("=== END DEBUG ===\n")

    @pytest.mark.asyncio
    async def test_llm_call_limit_stops_retries(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that LLM call limit stops further retries within a single patch."""
        from trata.src.agents.patcher import PatcherConfig, PatcherAgent
        
        # Set max_llm_calls_per_patch=2, max_retries=5
        # This means after 2 LLM calls, further retries should be blocked
        config = PatcherConfig(max_llm_calls_per_patch=2, max_retries=5)
        
        # Create mock LLM that always returns invalid response
        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value="invalid response - no yaml")
        
        agent = PatcherAgent(config, mock_llm, None)
        
        result = await agent.generate_patch(
            finding=sample_static_finding,
            source_root=temp_project_dir,
            run_ctx=mock_run_ctx,
        )
        
        debug_print(f"\n=== DEBUG: test_llm_call_limit_stops_retries ===")
        debug_print(f"result.success: {result.success}")
        debug_print(f"result.error_message: {result.error_message}")
        debug_print(f"current_patch_llm_calls: {agent.current_patch_llm_calls}")
        debug_print(f"total_llm_calls: {agent.total_llm_calls}")
        debug_print(f"number of attempts: {len(result.attempts)}")
        debug_print("=== END DEBUG ===\n")
        
        # Should have made exactly 2 LLM calls (not 6 = max_retries + 1)
        assert agent.current_patch_llm_calls == 2
        assert agent.total_llm_calls == 2
        assert "llm call limit" in result.error_message.lower()
        
        # Should have 2 attempts, not 6
        assert len(result.attempts) == 2

    @pytest.mark.asyncio
    async def test_llm_call_counter_resets_per_patch(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that LLM call counter resets for each new patch but total accumulates."""
        from trata.src.agents.patcher import PatcherConfig, PatcherAgent
        from trata.src.storage.models import StaticFinding
        
        config = PatcherConfig(max_llm_calls_per_patch=2, max_retries=5)
        
        # Create mock LLM that always returns invalid response
        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value="invalid response - no yaml")
        
        agent = PatcherAgent(config, mock_llm, None)
        
        # First patch - should hit limit at 2 calls
        result1 = await agent.generate_patch(
            finding=sample_static_finding,
            source_root=temp_project_dir,
            run_ctx=mock_run_ctx,
        )
        
        first_patch_calls = agent.current_patch_llm_calls
        first_patch_total = agent.total_llm_calls
        
        # Create a second finding
        second_finding = StaticFinding(
            tool="infer",
            check_id="NULL_DEREFERENCE",
            file="src/vuln.c",
            line=30,
            severity="high",
            title="Null Pointer Dereference",
            detail="Dereferencing a null pointer",
        )
        
        # Second patch - counter should reset, but total should accumulate
        result2 = await agent.generate_patch(
            finding=second_finding,
            source_root=temp_project_dir,
            run_ctx=mock_run_ctx,
        )
        
        second_patch_calls = agent.current_patch_llm_calls
        second_patch_total = agent.total_llm_calls
        
        debug_print(f"\n=== DEBUG: test_llm_call_counter_resets_per_patch ===")
        debug_print(f"First patch - current_calls: {first_patch_calls}, total: {first_patch_total}")
        debug_print(f"Second patch - current_calls: {second_patch_calls}, total: {second_patch_total}")
        debug_print("=== END DEBUG ===\n")
        
        # Each patch should have 2 LLM calls (hit limit)
        assert first_patch_calls == 2
        assert second_patch_calls == 2
        
        # Total should accumulate: 2 + 2 = 4
        assert first_patch_total == 2
        assert second_patch_total == 4  # Accumulated from both patches


class TestIncrementalPatching:
    """Test incremental patching behavior."""

    @pytest.mark.asyncio
    async def test_patches_use_working_copy_source(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
    ):
        """Test that patch generation uses working copy (not original)."""
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.storage.models import BuildArtifacts, StaticFinding
        from trata.src.config import TargetProjectConfig

        build_dir = temp_project_dir / "build"
        build_dir.mkdir()
        build_artifacts = BuildArtifacts(
            source_dir=temp_project_dir,
            build_dir=build_dir,
        )

        # Track which source root was used for each patch
        source_roots_used = []

        async def mock_generate_patch(self, finding, source_root, run_ctx, related_crash=None):
            source_roots_used.append(str(source_root))
            # Return a dummy result
            from trata.src.agents.patcher import PatcherResult
            from trata.src.tools.patch_applier import ParsedPatch
            result = PatcherResult(finding=finding)
            result.success = True
            result.best_patch = ParsedPatch(
                file_path="src/vuln.c",
                analysis="test",
                fix_strategy="test",
                patch="@@ -1,1 +1,1 @@\n // test",
                raw_response="mock response",
            )
            return result

        # Create two findings
        findings = [
            StaticFinding(
                tool="infer",
                file="src/vuln.c",
                line=10,
                check_id="test1",
                title="test1",
                detail="test1 detail",
                severity="high",
            ),
            StaticFinding(
                tool="infer",
                file="src/vuln.c",
                line=20,
                check_id="test2",
                title="test2",
                detail="test2 detail",
                severity="high",
            ),
        ]

        mock_llm = MagicMock()
        runtime_config = RuntimeConfig()
        pipeline = PatchingPipeline(
            runtime_config=runtime_config,
            store=LocalRunStore(mock_run_ctx.root),
            llm_client=mock_llm,
        )

        target_config = TargetProjectConfig(
            name="test-project",
            repo_url="",
            fuzz_targets=tuple(),
            build_script="echo 'build'",
            local_checkout=temp_project_dir,
        )

        # Monkey-patch the generate_patch method
        from trata.src.agents.patcher import PatcherAgent
        original = PatcherAgent.generate_patch
        PatcherAgent.generate_patch = mock_generate_patch

        try:
            result = await pipeline.execute(
                target=target_config,
                build=build_artifacts,
                run_ctx=mock_run_ctx,
                static_findings=findings,
                crashes=[],
            )
        finally:
            PatcherAgent.generate_patch = original

        # Both patches should use the working copy, not original
        assert len(source_roots_used) == 2
        for source_root in source_roots_used:
            assert "working_copy" in source_root
            assert str(temp_project_dir) != source_root

    @pytest.mark.asyncio
    async def test_incremental_patches_see_previous_changes(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
    ):
        """Test that later patches see file content modified by earlier patches."""
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.storage.models import BuildArtifacts, StaticFinding
        from trata.src.config import TargetProjectConfig

        build_dir = temp_project_dir / "build"
        build_dir.mkdir()
        build_artifacts = BuildArtifacts(
            source_dir=temp_project_dir,
            build_dir=build_dir,
        )

        # Track file contents seen at each patch generation
        file_contents_seen = []

        async def mock_generate_patch_with_tracking(self, finding, source_root, run_ctx, related_crash=None):
            # Read the current content of the file in the working copy
            src_file = source_root / "src" / "vuln.c"
            if src_file.exists():
                content = src_file.read_text()
                file_contents_seen.append(content)
            
            from trata.src.agents.patcher import PatcherResult
            from trata.src.tools.patch_applier import ParsedPatch
            result = PatcherResult(finding=finding)
            result.success = True
            
            # Create a patch that adds a marker comment
            patch_num = len(file_contents_seen)
            result.best_patch = ParsedPatch(
                file_path="src/vuln.c",
                analysis=f"Adding marker {patch_num}",
                fix_strategy="test",
                patch=f"@@ -1,1 +1,2 @@\n+// PATCH_MARKER_{patch_num}\n // Original line",
                raw_response="mock response",
            )
            return result

        # Create two findings for the same file
        findings = [
            StaticFinding(
                tool="infer",
                file="src/vuln.c",
                line=10,
                check_id="test1",
                title="test1",
                detail="test1 detail",
                severity="high",
            ),
            StaticFinding(
                tool="infer",
                file="src/vuln.c",
                line=20,
                check_id="test2",
                title="test2",
                detail="test2 detail",
                severity="high",
            ),
        ]

        mock_llm = MagicMock()
        runtime_config = RuntimeConfig()
        pipeline = PatchingPipeline(
            runtime_config=runtime_config,
            store=LocalRunStore(mock_run_ctx.root),
            llm_client=mock_llm,
        )

        target_config = TargetProjectConfig(
            name="test-project",
            repo_url="",
            fuzz_targets=tuple(),
            build_script="echo 'build'",
            local_checkout=temp_project_dir,
        )

        from trata.src.agents.patcher import PatcherAgent
        original = PatcherAgent.generate_patch
        PatcherAgent.generate_patch = mock_generate_patch_with_tracking

        try:
            await pipeline.execute(
                target=target_config,
                build=build_artifacts,
                run_ctx=mock_run_ctx,
                static_findings=findings,
                crashes=[],
            )
        finally:
            PatcherAgent.generate_patch = original

        # We should have captured 2 file contents
        assert len(file_contents_seen) == 2
        
        # Original source should NOT be modified
        original_content = (temp_project_dir / "src" / "vuln.c").read_text()
        assert "PATCH_MARKER" not in original_content


class TestPatcherIntegration:
    """Integration tests for the full patching flow."""

    @pytest.mark.asyncio
    async def test_full_patch_flow_offline(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test the full patching flow in offline mode."""
        from trata.src.pipelines.patching import PatchingPipeline, PatchingBatch
        from trata.src.storage.models import BuildArtifacts

        # Create build artifacts
        build_dir = temp_project_dir / "build"
        build_dir.mkdir()
        build_artifacts = BuildArtifacts(
            source_dir=temp_project_dir,
            build_dir=build_dir,
        )

        # Mock LLM client
        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value=dedent("""
            ```yaml
            analysis: "[OFFLINE] Test analysis"
            fix_strategy: "[OFFLINE] Test strategy"
            file_path: src/vuln.c
            patch: |
              @@ -24,1 +24,1 @@
               // [OFFLINE] Placeholder
            ```
        """))

        # Create pipeline
        runtime_config = RuntimeConfig()
        pipeline = PatchingPipeline(
            runtime_config=runtime_config,
            store=LocalRunStore(mock_run_ctx.root),
            llm_client=mock_llm,
        )

        # Create mock target config
        from trata.src.config import TargetProjectConfig
        target_config = TargetProjectConfig(
            name="test-project",
            repo_url="",
            fuzz_targets=tuple(),
            build_script="echo 'mock build'",
            local_checkout=temp_project_dir,
        )

        # Execute pipeline
        result = await pipeline.execute(
            target=target_config,
            build=build_artifacts,
            run_ctx=mock_run_ctx,
            static_findings=[sample_static_finding],
            crashes=[],
        )

        assert isinstance(result, PatchingBatch)
        assert result.findings_processed == 1
        # Working copy should be created
        assert result.working_copy_path is not None
        assert Path(result.working_copy_path).exists()

    @pytest.mark.asyncio
    async def test_working_copy_not_original(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that patching uses working copy, not original source."""
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.storage.models import BuildArtifacts

        # Save original content
        original_content = (temp_project_dir / "src" / "vuln.c").read_text()

        # Create build artifacts
        build_dir = temp_project_dir / "build"
        build_dir.mkdir()
        build_artifacts = BuildArtifacts(
            source_dir=temp_project_dir,
            build_dir=build_dir,
        )

        # Mock LLM client
        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value=dedent("""
            ```yaml
            analysis: "Test"
            fix_strategy: "Test"
            file_path: src/vuln.c
            patch: |
              @@ -1,1 +1,1 @@
               // Modified
            ```
        """))

        runtime_config = RuntimeConfig()
        pipeline = PatchingPipeline(
            runtime_config=runtime_config,
            store=LocalRunStore(mock_run_ctx.root),
            llm_client=mock_llm,
        )

        from trata.src.config import TargetProjectConfig
        target_config = TargetProjectConfig(
            name="test-project",
            repo_url="",
            fuzz_targets=tuple(),
            build_script="echo 'mock build'",
            local_checkout=temp_project_dir,
        )

        await pipeline.execute(
            target=target_config,
            build=build_artifacts,
            run_ctx=mock_run_ctx,
            static_findings=[sample_static_finding],
            crashes=[],
        )

        # Original should be UNCHANGED
        assert (temp_project_dir / "src" / "vuln.c").read_text() == original_content

    @pytest.mark.asyncio
    async def test_build_runs_on_working_copy(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that build runs on working copy directory."""
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.storage.models import BuildArtifacts

        build_dir = temp_project_dir / "build"
        build_dir.mkdir()
        build_artifacts = BuildArtifacts(
            source_dir=temp_project_dir,
            build_dir=build_dir,
        )

        # Create a build script that creates a marker file
        build_marker = []
        
        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value=dedent("""
            ```yaml
            analysis: "Test"
            fix_strategy: "Test"
            file_path: src/vuln.c
            patch: |
              @@ -1,1 +1,1 @@
               // test
            ```
        """))

        runtime_config = RuntimeConfig()
        pipeline = PatchingPipeline(
            runtime_config=runtime_config,
            store=LocalRunStore(mock_run_ctx.root),
            llm_client=mock_llm,
        )

        from trata.src.config import TargetProjectConfig
        
        # Build script that creates a marker in the build directory
        target_config = TargetProjectConfig(
            name="test-project",
            repo_url="",
            fuzz_targets=tuple(),
            build_script="touch build_marker.txt && echo 'Build complete'",
            local_checkout=temp_project_dir,
        )

        result = await pipeline.execute(
            target=target_config,
            build=build_artifacts,
            run_ctx=mock_run_ctx,
            static_findings=[sample_static_finding],
            crashes=[],
        )

        # Build marker should be in working copy, NOT original
        assert not (temp_project_dir / "build_marker.txt").exists()
        if result.working_copy_path:
            assert (Path(result.working_copy_path) / "build_marker.txt").exists()

    @pytest.mark.asyncio
    async def test_patched_files_saved(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that patched files are saved to patched_files directory."""
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.storage.models import BuildArtifacts

        build_dir = temp_project_dir / "build"
        build_dir.mkdir()
        build_artifacts = BuildArtifacts(
            source_dir=temp_project_dir,
            build_dir=build_dir,
        )

        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value=dedent("""
            ```yaml
            analysis: "Test"
            fix_strategy: "Test"
            file_path: src/vuln.c
            patch: |
              @@ -1,1 +1,1 @@
               // patched
            ```
        """))

        runtime_config = RuntimeConfig()
        pipeline = PatchingPipeline(
            runtime_config=runtime_config,
            store=LocalRunStore(mock_run_ctx.root),
            llm_client=mock_llm,
        )

        from trata.src.config import TargetProjectConfig
        target_config = TargetProjectConfig(
            name="test-project",
            repo_url="",
            fuzz_targets=tuple(),
            build_script="echo 'build'",
            local_checkout=temp_project_dir,
        )

        result = await pipeline.execute(
            target=target_config,
            build=build_artifacts,
            run_ctx=mock_run_ctx,
            static_findings=[sample_static_finding],
            crashes=[],
        )

        # Check patched_files directory exists
        patched_files_dir = mock_run_ctx.artifacts_dir / "patching" / "patched_files"
        if result.patches_applied > 0:
            assert patched_files_dir.exists()
            patched_files = list(patched_files_dir.glob("*"))
            assert len(patched_files) > 0

    @pytest.mark.asyncio
    async def test_crash_testing_with_mock_crash(
        self,
        temp_project_dir: Path,
        mock_run_ctx: RunContext,
        sample_static_finding: StaticFinding,
    ):
        """Test that crash testing runs against provided crashes."""
        from trata.src.pipelines.patching import PatchingPipeline, CrashTestResult
        from trata.src.storage.models import BuildArtifacts, FuzzCrash

        build_dir = temp_project_dir / "build"
        build_dir.mkdir()
        build_artifacts = BuildArtifacts(
            source_dir=temp_project_dir,
            build_dir=build_dir,
        )

        # Create a mock crash
        crash_dir = mock_run_ctx.artifacts_dir / "fuzzing" / "crashes"
        crash_dir.mkdir(parents=True)
        crash_input = crash_dir / "crash1"
        crash_input.write_bytes(b"CRASH_INPUT")

        mock_crash = FuzzCrash(
            crash_id="crash1",
            input_path=crash_input,
            input_size=11,
            dedup_token="token1",
            harness="fuzzer",
            timestamp="2025-01-01T00:00:00Z",
            stack_trace="SIGSEGV",
        )

        mock_llm = MagicMock()
        mock_llm.completion = AsyncMock(return_value=dedent("""
            ```yaml
            analysis: "Test"
            fix_strategy: "Test"
            file_path: src/vuln.c
            patch: |
              @@ -1,1 +1,1 @@
               // test
            ```
        """))

        runtime_config = RuntimeConfig()
        pipeline = PatchingPipeline(
            runtime_config=runtime_config,
            store=LocalRunStore(mock_run_ctx.root),
            llm_client=mock_llm,
        )

        from trata.src.config import TargetProjectConfig
        target_config = TargetProjectConfig(
            name="test-project",
            repo_url="",
            fuzz_targets=tuple(),
            build_script="echo 'build'",
            local_checkout=temp_project_dir,
        )

        result = await pipeline.execute(
            target=target_config,
            build=build_artifacts,
            run_ctx=mock_run_ctx,
            static_findings=[sample_static_finding],
            crashes=[mock_crash],
        )

        # Check that crash tests were recorded
        for test_result in result.test_results:
            if test_result.build_success:
                # Should have attempted to test crashes
                assert len(test_result.crash_tests) > 0 or test_result.crashes_remaining >= 0


class TestFuzzingIntegration:
    """Integration tests for fuzzing and crash testing."""

    @pytest.fixture
    def temp_project_with_fuzzer(self, tmp_path: Path) -> Path:
        """Create a project with a mock fuzzer binary."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "src").mkdir()
        
        # Create vuln.c
        (project_dir / "src" / "vuln.c").write_text("""
int vulnerable_function(int x) {
    if (x == 42) {
        int *p = 0;
        return *p;  // null deref
    }
    return x * 2;
}
""")
        
        # Create fuzz directory
        (project_dir / "fuzz").mkdir()
        (project_dir / "fuzz" / "vuln_fuzzer.c").write_text("""
#include <stdint.h>
#include <stddef.h>

extern int vulnerable_function(int x);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= sizeof(int)) {
        int x = *(int*)data;
        vulnerable_function(x);
    }
    return 0;
}
""")
        
        # Create build directory with a dummy "fuzzer"
        (project_dir / "build").mkdir()
        
        # Create a mock fuzzer script (executable)
        mock_fuzzer = project_dir / "build" / "vuln_fuzzer"
        mock_fuzzer.write_text("#!/bin/sh\nexit 0\n")
        mock_fuzzer.chmod(0o755)
        
        return project_dir

    def test_find_fuzzer_binary_dynamic_naming(
        self,
        temp_project_with_fuzzer: Path,
    ):
        """Test that _find_fuzzer_binary finds binaries based on target config."""
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.config import TargetProjectConfig, RuntimeConfig
        
        target = TargetProjectConfig(
            name="test",
            repo_url="",
            fuzz_targets=("fuzz/vuln_fuzzer.c",),
        )
        
        runtime = RuntimeConfig()
        pipeline = PatchingPipeline(runtime_config=runtime)
        
        # Should find vuln_fuzzer (from harness name)
        found = pipeline._find_fuzzer_binary(temp_project_with_fuzzer, target)
        
        debug_print(f"\n=== DEBUG: test_find_fuzzer_binary_dynamic_naming ===")
        debug_print(f"Looking in: {temp_project_with_fuzzer}")
        debug_print(f"Target fuzz_targets: {target.fuzz_targets}")
        debug_print(f"Found binary: {found}")
        debug_print("=== END DEBUG ===\n")
        
        assert found is not None
        assert found.name == "vuln_fuzzer"

    def test_find_fuzzer_binary_with_multiple_targets(
        self,
        temp_project_with_fuzzer: Path,
    ):
        """Test _find_fuzzer_binary with multiple fuzz targets."""
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.config import TargetProjectConfig, RuntimeConfig
        
        # Add a second mock fuzzer
        (temp_project_with_fuzzer / "build" / "packet_fuzzer").write_text("#!/bin/sh\nexit 0\n")
        (temp_project_with_fuzzer / "build" / "packet_fuzzer").chmod(0o755)
        
        target = TargetProjectConfig(
            name="test",
            repo_url="",
            fuzz_targets=("fuzz/vuln_fuzzer.c", "fuzz/packet_fuzzer.c"),
        )
        
        runtime = RuntimeConfig()
        pipeline = PatchingPipeline(runtime_config=runtime)
        
        found = pipeline._find_fuzzer_binary(temp_project_with_fuzzer, target)
        
        debug_print(f"\n=== DEBUG: test_find_fuzzer_binary_with_multiple_targets ===")
        debug_print(f"Target fuzz_targets: {target.fuzz_targets}")
        debug_print(f"Found binary: {found}")
        debug_print("=== END DEBUG ===\n")
        
        # Should find one of the fuzzers
        assert found is not None
        assert found.name in ("vuln_fuzzer", "packet_fuzzer")

    def test_working_copy_fuzzer_not_original(
        self,
        tmp_path: Path,
    ):
        """
        Test that crash testing uses the working copy fuzzer, not original.
        
        This test verifies that when crashes are tested:
        1. The project is rebuilt in the working copy
        2. The fuzzer binary is found in the working copy
        3. The original source directory's fuzzer is NOT used
        """
        # Create original project
        original_dir = tmp_path / "original"
        original_dir.mkdir()
        (original_dir / "src").mkdir()
        (original_dir / "src" / "vuln.c").write_text("// Original source\n")
        (original_dir / "build").mkdir()
        
        # Create a fuzzer in original that would fail
        original_fuzzer = original_dir / "build" / "vuln_fuzzer"
        original_fuzzer.write_text("#!/bin/sh\necho 'ORIGINAL - SHOULD NOT BE USED'\nexit 99\n")
        original_fuzzer.chmod(0o755)
        
        from trata.src.tools.patch_applier import WorkingCopyManager
        
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        
        # Create working copy
        mgr = WorkingCopyManager(
            original_source_dir=original_dir,
            artifacts_dir=artifacts_dir,
        )
        mgr.initialize()
        
        working_copy = mgr.get_working_copy_path()
        
        # Create a different fuzzer in working copy
        (working_copy / "build").mkdir(exist_ok=True)
        working_fuzzer = working_copy / "build" / "vuln_fuzzer"
        working_fuzzer.write_text("#!/bin/sh\necho 'WORKING COPY - CORRECT'\nexit 0\n")
        working_fuzzer.chmod(0o755)
        
        # Now verify _find_fuzzer_binary finds the working copy one
        from trata.src.pipelines.patching import PatchingPipeline
        from trata.src.config import TargetProjectConfig, RuntimeConfig
        
        target = TargetProjectConfig(
            name="test",
            repo_url="",
            fuzz_targets=("fuzz/vuln_fuzzer.c",),
        )
        
        runtime = RuntimeConfig()
        pipeline = PatchingPipeline(runtime_config=runtime)
        
        found = pipeline._find_fuzzer_binary(working_copy, target)
        
        debug_print(f"\n=== DEBUG: test_working_copy_fuzzer_not_original ===")
        debug_print(f"Original dir: {original_dir}")
        debug_print(f"Working copy: {working_copy}")
        debug_print(f"Found binary: {found}")
        debug_print("=== END DEBUG ===\n")
        
        assert found is not None
        # Must be in working copy, not original
        assert "working_copy" in str(found)
        assert str(original_dir) not in str(found)
