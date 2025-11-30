"""
Patch applier for the V1 patcher agent.

Handles parsing LLM responses and applying unified diff patches.

ARCHITECTURE:
- Creates a WORKING COPY of the source directory for patching
- Original source is NEVER modified
- Patches are applied CUMULATIVELY to the working copy
- Each patched file version is SAVED to artifacts/patching/patched_files/
- Build and test use the working copy
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

import yaml


@dataclass()
class PatchResult:
    """Result of applying a patch."""

    success: bool
    file_path: str  # Relative path in project
    original_content: str
    patched_content: str
    error_message: Optional[str] = None
    validation_errors: List[str] = field(default_factory=list)
    patch_hash: Optional[str] = None  # Hash of the patch for deduplication


@dataclass()
class ParsedPatch:
    """Parsed patch from LLM response."""

    analysis: str
    fix_strategy: str
    file_path: str
    patch: str
    raw_response: str


class PatchParser:
    """Parses LLM responses to extract patch information."""

    @staticmethod
    def parse_yaml_response(response: str) -> Optional[ParsedPatch]:
        """
        Extract YAML-formatted patch from LLM response.

        Expected format:
        ```yaml
        analysis: ...
        fix_strategy: ...
        file_path: ...
        patch: |
          @@ -line,count +line,count @@
          ...
        ```
        """
        # Try to find YAML block
        yaml_patterns = [
            r"```yaml\s*(.*?)```",
            r"```yml\s*(.*?)```",
            r"```\s*(analysis:.*?)```",
        ]

        yaml_content = None
        for pattern in yaml_patterns:
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                yaml_content = match.group(1).strip()
                break

        if not yaml_content:
            # Try parsing the entire response as YAML
            if "analysis:" in response and "patch:" in response:
                yaml_content = response

        if not yaml_content:
            return None

        try:
            parsed = yaml.safe_load(yaml_content)
            if not isinstance(parsed, dict):
                return None

            # Validate required fields
            required_fields = ["analysis", "fix_strategy", "file_path", "patch"]
            for field_name in required_fields:
                if field_name not in parsed:
                    return None

            return ParsedPatch(
                analysis=str(parsed.get("analysis", "")),
                fix_strategy=str(parsed.get("fix_strategy", "")),
                file_path=str(parsed.get("file_path", "")),
                patch=str(parsed.get("patch", "")),
                raw_response=response,
            )
        except yaml.YAMLError:
            return None

    @staticmethod
    def extract_unified_diff(text: str) -> Optional[str]:
        """
        Extract unified diff from text, handling various formats.
        """
        # Look for diff blocks
        diff_pattern = r"(@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@.*?)(?=\n@@ |\n```|\Z)"
        matches = re.findall(diff_pattern, text, re.DOTALL)

        if matches:
            return "\n".join(matches)

        # Try to find diff-like content
        lines = text.split("\n")
        diff_lines = []
        in_diff = False

        for line in lines:
            if line.startswith("@@"):
                in_diff = True
            if in_diff:
                if line.startswith(("@@", " ", "+", "-")) or line.strip() == "":
                    diff_lines.append(line)
                elif line.startswith("```"):
                    break

        if diff_lines:
            return "\n".join(diff_lines)

        return None


class WorkingCopyManager:
    """
    Manages a working copy of the source directory for patching.
    
    The working copy is used for:
    - Applying patches without modifying original source
    - Cumulative patching (each patch builds on previous)
    - Building and testing with patched code
    """

    def __init__(
        self,
        original_source_dir: Path,
        artifacts_dir: Path,
        logger_func: Optional[callable] = None,
    ):
        self.original_source_dir = original_source_dir
        self.artifacts_dir = artifacts_dir
        self.logger = logger_func or print
        
        # Working copy location
        self.working_copy_dir = artifacts_dir / "patching" / "working_copy"
        
        # Directory for saved patched files
        self.patched_files_dir = artifacts_dir / "patching" / "patched_files"
        
        # Backup directory for rollback
        self.backup_dir = artifacts_dir / "patching" / "backups"
        
        self._initialized = False

    def initialize(self) -> bool:
        """
        Create a fresh working copy of the source directory.
        
        Returns True if successful, False otherwise.
        """
        try:
            # Clean up any existing working copy
            if self.working_copy_dir.exists():
                shutil.rmtree(self.working_copy_dir)
            
            # Create parent directories for working copy
            self.working_copy_dir.parent.mkdir(parents=True, exist_ok=True)
            self.patched_files_dir.mkdir(parents=True, exist_ok=True)
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy source to working copy, excluding artifacts directory to avoid recursion
            self.logger(f"Creating working copy of source: {self.original_source_dir}")
            
            def ignore_func(directory: str, files: list[str]) -> list[str]:
                """Ignore artifacts, build outputs, and hidden directories."""
                ignored = []
                for f in files:
                    full_path = Path(directory) / f
                    # Ignore artifacts directory to prevent recursion
                    if "artifacts" in str(full_path):
                        ignored.append(f)
                    # Ignore common build/cache files
                    elif f.endswith(('.o', '.a', '.so', '.pyc')):
                        ignored.append(f)
                    elif f in ('__pycache__', '.git', 'build', 'data'):
                        ignored.append(f)
                return ignored
            
            shutil.copytree(
                self.original_source_dir,
                self.working_copy_dir,
                ignore=ignore_func,
            )
            
            self._initialized = True
            self.logger(f"Working copy created at: {self.working_copy_dir}")
            return True
            
        except Exception as e:
            self.logger(f"ERROR: Failed to create working copy: {e}")
            return False

    def get_working_copy_path(self) -> Path:
        """Get the path to the working copy directory."""
        if not self._initialized:
            raise RuntimeError("WorkingCopyManager not initialized. Call initialize() first.")
        return self.working_copy_dir

    def create_file_backup(self, relative_path: str) -> Optional[Path]:
        """
        Create a backup of a file in the working copy before patching.
        
        Returns the backup path, or None if failed.
        """
        source_file = self.working_copy_dir / relative_path
        if not source_file.exists():
            return None
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        safe_name = relative_path.replace("/", "_").replace("\\", "_")
        backup_path = self.backup_dir / f"{safe_name}.{timestamp}.bak"
        
        try:
            shutil.copy2(source_file, backup_path)
            self.logger(f"Created backup: {backup_path.name}")
            return backup_path
        except Exception as e:
            self.logger(f"ERROR: Failed to create backup: {e}")
            return None

    def restore_from_backup(self, relative_path: str, backup_path: Path) -> bool:
        """
        Restore a file from backup (rollback).
        
        Returns True if successful.
        """
        if not backup_path or not backup_path.exists():
            self.logger(f"ERROR: Backup file not found: {backup_path}")
            return False
        
        target_file = self.working_copy_dir / relative_path
        
        try:
            shutil.copy2(backup_path, target_file)
            backup_path.unlink()  # Delete backup after successful restore
            self.logger(f"Restored file from backup: {relative_path}")
            return True
        except Exception as e:
            self.logger(f"ERROR: Failed to restore from backup: {e}")
            # Attempt emergency restore from original source
            return self._emergency_restore(relative_path)

    def _emergency_restore(self, relative_path: str) -> bool:
        """
        Emergency restore from original source if backup restore fails.
        """
        original_file = self.original_source_dir / relative_path
        target_file = self.working_copy_dir / relative_path
        
        if not original_file.exists():
            self.logger(f"ERROR: Emergency restore failed - original not found: {original_file}")
            return False
        
        try:
            shutil.copy2(original_file, target_file)
            self.logger(f"EMERGENCY RESTORE successful: {relative_path}")
            return True
        except Exception as e:
            self.logger(f"ERROR: Emergency restore failed: {e}")
            return False

    def save_patched_file(self, relative_path: str, patch_index: int, finding_id: str) -> Optional[Path]:
        """
        Save a copy of the patched file to the patched_files directory.
        
        Returns the path to the saved file.
        """
        source_file = self.working_copy_dir / relative_path
        if not source_file.exists():
            return None
        
        # Create a meaningful filename
        safe_name = relative_path.replace("/", "_").replace("\\", "_")
        safe_finding = re.sub(r'[^\w\-_]', '_', finding_id)[:50]
        saved_name = f"patch_{patch_index:03d}_{safe_name}_{safe_finding}"
        saved_path = self.patched_files_dir / saved_name
        
        try:
            shutil.copy2(source_file, saved_path)
            self.logger(f"Saved patched file: {saved_path.name}")
            return saved_path
        except Exception as e:
            self.logger(f"ERROR: Failed to save patched file: {e}")
            return None

    def get_file_content(self, relative_path: str) -> Optional[str]:
        """Get the current content of a file in the working copy."""
        file_path = self.working_copy_dir / relative_path
        if not file_path.exists():
            return None
        try:
            return file_path.read_text()
        except Exception:
            return None

    def cleanup(self):
        """Clean up the working copy (optional, for when done)."""
        # Keep the working copy for inspection, but clean up backups
        if self.backup_dir.exists():
            for backup_file in self.backup_dir.glob("*.bak"):
                try:
                    backup_file.unlink()
                except Exception:
                    pass


class PatchApplier:
    """
    Applies unified diff patches to source files.
    
    Works with WorkingCopyManager to apply patches cumulatively.
    """

    def __init__(self, working_copy_dir: Path, logger_func: Optional[callable] = None):
        """
        Initialize the patch applier.
        
        Args:
            working_copy_dir: Path to the working copy (NOT original source)
            logger_func: Optional logging function
        """
        self.working_copy_dir = working_copy_dir
        self.logger = logger_func or print

    def validate_patch(self, file_path: str, patch_content: str) -> List[str]:
        """
        Validate a patch before applying.
        
        Returns a list of validation errors (empty if valid).
        """
        errors = []
        
        # Check file exists
        target_file = self.working_copy_dir / file_path
        if not target_file.exists():
            errors.append(f"Target file not found: {file_path}")
            return errors
        
        # Check patch has hunks
        if "@@ -" not in patch_content:
            errors.append("Patch does not contain valid hunk headers (@@ -...)")
        
        # Check for obviously broken patches
        if "// [OFFLINE]" in patch_content and patch_content.count("\n") < 3:
            errors.append("Patch appears to be an offline placeholder")
        
        # Check hunk format
        hunk_pattern = r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
        hunks = re.findall(hunk_pattern, patch_content)
        if not hunks:
            errors.append("No valid hunk headers found in patch")
        
        return errors

    def apply_patch(
        self,
        file_path: str,
        patch_content: str,
        validate: bool = True,
    ) -> PatchResult:
        """
        Apply a unified diff patch to a file in the working copy.

        Args:
            file_path: Relative path to the file to patch
            patch_content: Unified diff content
            validate: Whether to validate the patch first

        Returns:
            PatchResult with success status and details
        """
        target_file = self.working_copy_dir / file_path

        if not target_file.exists():
            return PatchResult(
                success=False,
                file_path=file_path,
                original_content="",
                patched_content="",
                error_message=f"File not found: {target_file}",
            )

        # Read original content
        try:
            original_content = target_file.read_text()
        except Exception as e:
            return PatchResult(
                success=False,
                file_path=file_path,
                original_content="",
                patched_content="",
                error_message=f"Failed to read file: {e}",
            )

        # Validate patch
        validation_errors = []
        if validate:
            validation_errors = self.validate_patch(file_path, patch_content)
            if validation_errors:
                self.logger(f"Patch validation warnings: {validation_errors}")
                # Don't fail on validation errors, just log them

        # Calculate patch hash for deduplication
        patch_hash = hashlib.sha256(patch_content.encode()).hexdigest()[:16]

        # Try to apply patch using the `patch` command
        result = self._apply_with_patch_command(
            target_file, patch_content, file_path, original_content
        )

        if not result.success:
            # Try manual application
            self.logger("Patch command failed, trying manual application...")
            result = self._apply_manually(
                target_file, patch_content, original_content, file_path
            )

        result.validation_errors = validation_errors
        result.patch_hash = patch_hash
        return result

    def _apply_with_patch_command(
        self,
        target_file: Path,
        patch_content: str,
        file_path: str,
        original_content: str,
    ) -> PatchResult:
        """Try to apply patch using the system `patch` command."""
        # Create a proper patch file with headers
        filename = target_file.name
        patch_with_headers = f"""--- a/{filename}
+++ b/{filename}
{patch_content}
"""

        try:
            # Try applying with patch -p0 (no path stripping)
            result = subprocess.run(
                ["patch", "-p0", "--forward", "--no-backup-if-mismatch", "-r", "-"],
                input=patch_with_headers,
                capture_output=True,
                text=True,
                cwd=target_file.parent,
                timeout=30,
            )

            if result.returncode == 0:
                patched_content = target_file.read_text()
                self.logger(f"Patch applied successfully via 'patch' command")
                return PatchResult(
                    success=True,
                    file_path=file_path,
                    original_content=original_content,
                    patched_content=patched_content,
                )
            else:
                # Restore original if patch failed partway
                target_file.write_text(original_content)
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                return PatchResult(
                    success=False,
                    file_path=file_path,
                    original_content=original_content,
                    patched_content=original_content,
                    error_message=f"patch command failed: {error_msg[:200]}",
                )

        except FileNotFoundError:
            return PatchResult(
                success=False,
                file_path=file_path,
                original_content=original_content,
                patched_content=original_content,
                error_message="patch command not found - falling back to manual",
            )
        except subprocess.TimeoutExpired:
            return PatchResult(
                success=False,
                file_path=file_path,
                original_content=original_content,
                patched_content=original_content,
                error_message="patch command timed out",
            )
        except Exception as e:
            return PatchResult(
                success=False,
                file_path=file_path,
                original_content=original_content,
                patched_content=original_content,
                error_message=f"patch command error: {e}",
            )

    def _apply_manually(
        self,
        target_file: Path,
        patch_content: str,
        original_content: str,
        file_path: str,
    ) -> PatchResult:
        """
        Manually apply a unified diff patch.

        This is a fallback implementation for when the patch command fails.
        """
        try:
            lines = original_content.split("\n")
            hunks = self._parse_hunks(patch_content)

            if not hunks:
                return PatchResult(
                    success=False,
                    file_path=file_path,
                    original_content=original_content,
                    patched_content=original_content,
                    error_message="No valid hunks found in patch",
                )

            # Apply hunks in reverse order to preserve line numbers
            for hunk in reversed(hunks):
                lines = self._apply_hunk(lines, hunk)

            patched_content = "\n".join(lines)
            target_file.write_text(patched_content)

            self.logger(f"Patch applied successfully via manual application")
            return PatchResult(
                success=True,
                file_path=file_path,
                original_content=original_content,
                patched_content=patched_content,
            )

        except Exception as e:
            # Restore original on failure
            target_file.write_text(original_content)
            return PatchResult(
                success=False,
                file_path=file_path,
                original_content=original_content,
                patched_content=original_content,
                error_message=f"Manual patch failed: {e}",
            )

    def _parse_hunks(self, patch_content: str) -> list[dict]:
        """Parse unified diff into hunks."""
        hunks = []
        hunk_pattern = r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"

        current_hunk = None
        for line in patch_content.split("\n"):
            match = re.match(hunk_pattern, line)
            if match:
                if current_hunk:
                    hunks.append(current_hunk)
                current_hunk = {
                    "old_start": int(match.group(1)),
                    "old_count": int(match.group(2)) if match.group(2) else 1,
                    "new_start": int(match.group(3)),
                    "new_count": int(match.group(4)) if match.group(4) else 1,
                    "lines": [],
                }
            elif current_hunk is not None:
                if line.startswith("+"):
                    current_hunk["lines"].append(("+", line[1:]))
                elif line.startswith("-"):
                    current_hunk["lines"].append(("-", line[1:]))
                elif line.startswith(" "):
                    current_hunk["lines"].append((" ", line[1:]))
                elif line == "":
                    # Empty line in diff context
                    current_hunk["lines"].append((" ", ""))

        if current_hunk:
            hunks.append(current_hunk)

        return hunks

    def _apply_hunk(self, lines: list[str], hunk: dict) -> list[str]:
        """Apply a single hunk to the lines."""
        # Convert to 0-indexed
        start_line = hunk["old_start"] - 1
        new_lines = []

        # Build new content from hunk
        for op, content in hunk["lines"]:
            if op == "+":
                new_lines.append(content)
            elif op == " ":
                new_lines.append(content)
            # '-' lines are removed, so we don't add them

        # Calculate how many lines to remove
        lines_to_remove = sum(1 for op, _ in hunk["lines"] if op in ("-", " "))

        # Apply the replacement
        result = lines[:start_line] + new_lines + lines[start_line + lines_to_remove :]
        return result
