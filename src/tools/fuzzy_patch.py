"""
Fuzzy Patch Application using Smith-Waterman Alignment.

This module provides robust patch application that doesn't rely on exact line
numbers. Instead, it uses sequence alignment to find where patch context lines
best match in the source file.

Adapted from theori's CRS implementation (crs/common/fuzzy_patch.py).
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Literal, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Constants
HUNK_HEADER_RE = re.compile(r"\A@@\s-(\d*),?\d*\s\+\d*,?\d*\s@@")
NEW_SENTINEL = "+~NEW~+"
GAP_CHAR = "+~GAP~+"


# ==============================================================================
# Result types
# ==============================================================================

@dataclass
class FuzzyPatchError:
    """Error from fuzzy patch application."""
    message: str
    extra: dict = field(default_factory=dict)


@dataclass
class FuzzyPatchResult:
    """Result of fuzzy patch application."""
    success: bool
    new_content: str = ""
    error: Optional[FuzzyPatchError] = None
    matched_lines: List[Tuple[Optional[int], Optional[int]]] = field(default_factory=list)


# ==============================================================================
# Scoring and matching
# ==============================================================================

class MatchScorer:
    """
    Scores similarity between lines using edit distance.
    
    Based on theori's CRS implementation.
    """
    
    def __init__(self) -> None:
        self.delete_weight = 1.0
        self.match_weight = 0.0
        self.sub_weight = 1.5
        self.max_distance = 5
        self.alignment_mismatch = -0.5
    
    def char_score(self, a: str, b: str) -> float:
        """Score similarity between two characters."""
        if a == b:
            return self.match_weight
        # Lower penalty for mismatched numbers (timestamps, etc.)
        if a.isdigit() and b.isdigit():
            return self.sub_weight / 10
        # Lower penalty for case mismatch
        if a.lower() == b.lower():
            return self.sub_weight / 10
        return self.sub_weight
    
    def __call__(self, a: str, b: str) -> float:
        """
        Return a similarity score between two lines.
        
        Higher is better. Uses edit distance internally.
        """
        # Identical lines
        if a == b:
            if len(a) == 0:
                return 1.0
            return len(a).bit_length() ** 0.5
        
        # Special sentinels for new/gap
        if NEW_SENTINEL in (a, b) and GAP_CHAR in (a, b):
            return 0.01
        if "" in (a, b) and GAP_CHAR in (a, b):
            return -0.01
        
        cutoff = min(len(a), len(b), self.max_distance)
        
        # Very different lengths = bad match
        if abs(len(a) - len(b)) > cutoff:
            return self.alignment_mismatch
        
        # Strip common prefix for speed
        common_prefix_len = 0
        for i in range(min(len(a), len(b))):
            if a[i] != b[i]:
                break
            common_prefix_len = i + 1
        
        a_tail = a[common_prefix_len:]
        b_tail = b[common_prefix_len:]
        
        n, m = len(a_tail), len(b_tail)
        
        # Wagner-Fischer edit distance
        dist = np.zeros((n + 1, m + 1))
        for i in range(1, n + 1):
            dist[i, 0] = self.delete_weight * i
        for j in range(1, m + 1):
            dist[0, j] = self.delete_weight * j
        
        for i in range(1, n + 1):
            early_exit = True
            for j in range(1, m + 1):
                score = max(
                    dist[i - 1, j - 1] + self.char_score(a_tail[i - 1], b_tail[j - 1]),
                    dist[i - 1, j] + self.delete_weight,
                    dist[i, j - 1] + self.delete_weight,
                )
                dist[i, j] = score
                if score < cutoff:
                    early_exit = False
            if early_exit:
                return self.alignment_mismatch
        
        factor = (1 - dist[n, m] / self.max_distance) ** 2
        return min(n, m).bit_length() ** 0.5 * factor


class SWMatcher:
    """
    Smith-Waterman local sequence alignment for lines.
    
    This finds the best local alignment between source file lines
    and patch context lines, allowing fuzzy matching.
    """
    
    def __init__(self) -> None:
        self.scorer = MatchScorer()
    
    def get_alignment(
        self, seq1: List[str], seq2: List[str]
    ) -> np.ndarray:
        """
        Build the Smith-Waterman score matrix.
        
        Args:
            seq1: Source file lines
            seq2: Patch context lines
            
        Returns:
            Score matrix (n+1, m+1)
        """
        n, m = len(seq1), len(seq2)
        mat = np.zeros((n + 1, m + 1))
        
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                score = max(
                    mat[i - 1, j - 1] + self.scorer(seq1[i - 1], seq2[j - 1]),
                    mat[i - 1, j] + self.scorer(seq1[i - 1], GAP_CHAR),
                    mat[i, j - 1] + self.scorer(seq2[j - 1], GAP_CHAR),
                    0,
                )
                mat[i, j] = score
        
        return mat
    
    def backtrack(
        self,
        score_matrix: np.ndarray,
        seq1: List[str],
        seq2: List[str],
    ) -> List[Tuple[Optional[int], Optional[int]]]:
        """
        Backtrack through the score matrix to find the alignment.
        
        Returns:
            List of (source_idx, patch_idx) tuples.
            None values indicate gaps.
        """
        aligned_pairs: List[Tuple[Optional[int], Optional[int]]] = []
        
        # Find the cell with maximum score
        i, j = np.unravel_index(np.argmax(score_matrix), score_matrix.shape)
        
        # Backtrack until we hit a 0
        while score_matrix[i, j] != 0:
            match_score = score_matrix[i - 1, j - 1] + self.scorer(seq1[i - 1], seq2[j - 1])
            delete_score = score_matrix[i - 1, j] + self.scorer(seq1[i - 1], GAP_CHAR)
            insert_score = score_matrix[i, j - 1] + self.scorer(seq2[j - 1], GAP_CHAR)
            
            max_score = max(match_score, delete_score, insert_score)
            
            # Prefer match > delete > insert
            if abs(match_score - max_score) < 1e-9:
                i -= 1
                j -= 1
                aligned_pairs.append((i, j))
            elif abs(delete_score - max_score) < 1e-9:
                i -= 1
                aligned_pairs.append((i, None))
            else:
                j -= 1
                aligned_pairs.append((None, j))
        
        # Reverse to get forward order
        return aligned_pairs[::-1]


# ==============================================================================
# Patch parsing
# ==============================================================================

EditType = Literal['+', '-', '']


@dataclass
class Hunk:
    """A single hunk from a unified diff."""
    relpath: str
    elines: List[Tuple[EditType, str]]
    line_number: int  # Estimated line number (may be inaccurate)


def is_file_header(line: str) -> bool:
    """Check if line is a file header (--- or +++)."""
    return line.startswith("--- ") or line.startswith("+++ ")


def is_hunk_header(line: str) -> bool:
    """Check if line is a hunk header (@@ ... @@)."""
    return HUNK_HEADER_RE.match(line) is not None


def is_context_line(line: str) -> bool:
    """Check if line is a context line (starts with space)."""
    return line.startswith(" ")


def is_edit_line(line: str) -> bool:
    """Check if line is an edit line (+ or -)."""
    return (line.startswith("+") or line.startswith("-")) and not is_file_header(line)


def cleanup_patch_line(line: str) -> str:
    """Cleanup a single patch line."""
    if is_file_header(line) or is_hunk_header(line):
        return line
    if is_context_line(line) or is_edit_line(line):
        return line
    # LLM sometimes omits leading space on context lines
    return " " + line


def parse_hunks(relpath: str, patch: str) -> List[Hunk]:
    """
    Parse a unified diff into hunks.
    
    Args:
        relpath: Relative path to the file
        patch: Patch content
        
    Returns:
        List of Hunk objects
    """
    hunks: List[Hunk] = []
    current_hunk: Optional[Hunk] = None
    
    for line in patch.splitlines():
        if is_file_header(line):
            continue
        
        if match := HUNK_HEADER_RE.match(line):
            if current_hunk is not None:
                hunks.append(current_hunk)
            
            # Extract estimated line number
            line_no_str = match.group(1)
            line_no = int(line_no_str) if line_no_str else 1
            current_hunk = Hunk(relpath, [], line_no)
        
        elif current_hunk is not None:
            # Determine edit type
            if line.startswith("+"):
                edit_type: EditType = "+"
            elif line.startswith("-"):
                edit_type = "-"
            else:
                edit_type = ""
            
            # Strip the leading marker
            content = line[1:] if line and line[0] in "+-" else line[1:] if line.startswith(" ") else line
            current_hunk.elines.append((edit_type, content))
    
    if current_hunk is not None:
        hunks.append(current_hunk)
    
    return hunks


# ==============================================================================
# Alignment helpers
# ==============================================================================

def norm_whitespace(lines: List[str]) -> List[str]:
    """Normalize whitespace in lines for comparison."""
    return [' '.join(s.split()) for s in lines]


def find_alignment(
    source_lines: List[str],
    patch_lines: List[str],
    est_line: Optional[int] = None,
) -> Tuple[List[Tuple[Optional[int], Optional[int]]], Optional[str]]:
    """
    Find alignment between source and patch lines.
    
    Args:
        source_lines: Lines from source file
        patch_lines: Lines from patch (context + edits)
        est_line: Estimated line number (hint)
        
    Returns:
        (alignment, error_message)
        alignment is list of (source_idx, patch_idx) tuples
    """
    # Normalize for comparison
    norm_source = norm_whitespace(source_lines)
    norm_patch = norm_whitespace(patch_lines)
    
    matcher = SWMatcher()
    mat = matcher.get_alignment(norm_source, norm_patch)
    
    top_score = mat.max()
    winners = np.count_nonzero(mat == top_score)
    
    if top_score < 2.0:
        return [], "No good matches found - context lines don't match source"
    
    if winners > 1:
        # Multiple matches - try to disambiguate using estimated line number
        if est_line is not None:
            patch_mid = len(patch_lines) / 2
            est_sites = np.where(mat == top_score)[0]
            
            valid_sites = []
            for site in est_sites:
                if abs((est_line - patch_mid) - site) < 10:
                    valid_sites.append(site)
                else:
                    # Zero out scores far from estimated line
                    mat[site] = 0
            
            if len(valid_sites) != 1:
                return [], (
                    f"Context matched {winners} locations. "
                    "Please provide more context or verify context correctness."
                )
            
            logger.debug(f"Ambiguous match resolved using line hint at {valid_sites[0]}")
        else:
            return [], (
                f"Context matched {winners} locations. "
                "Cannot disambiguate without line number hint."
            )
    
    # Backtrack to get alignment
    alignment = matcher.backtrack(mat, norm_source, norm_patch)
    return alignment, None


# ==============================================================================
# Main fuzzy patch application
# ==============================================================================

@dataclass
class HunkApplicationResult:
    """Result of applying a single hunk."""
    new_lines: List[str]
    error: Optional[str] = None
    matched_line_start: Optional[int] = None  # 1-indexed line number where match was found
    matched_line_end: Optional[int] = None
    estimated_line: Optional[int] = None  # Line number from patch header
    line_offset: Optional[int] = None  # Difference between estimated and actual


def apply_hunk(
    source_lines: List[str],
    hunk: Hunk,
) -> Tuple[List[str], Optional[str], Optional[dict]]:
    """
    Apply a single hunk using fuzzy matching.
    
    Args:
        source_lines: Original source lines
        hunk: Hunk to apply
        
    Returns:
        (new_lines, error_message, match_info)
        match_info contains: estimated_line, actual_line, offset
    """
    # Build patch lines (replacing additions with sentinel)
    patch_lines = [
        line if edit_type != '+' else NEW_SENTINEL
        for edit_type, line in hunk.elines
    ]
    
    if not source_lines:
        # Empty file - just add all additions
        new_lines = [line for edit_type, line in hunk.elines if edit_type != '-']
        return new_lines, None, {"estimated_line": hunk.line_number, "actual_line": 1, "offset": 0}
    
    # Find alignment
    alignment, error = find_alignment(source_lines, patch_lines, hunk.line_number)
    if error:
        return [], error, None
    
    if not alignment:
        return [], "Alignment produced no matches", None
    
    # Get the range of matched source lines
    first_match_src = None
    last_match_src = None
    for src_idx, _ in alignment:
        if src_idx is not None:
            if first_match_src is None:
                first_match_src = src_idx
            last_match_src = src_idx
    
    if first_match_src is None:
        return [], "No source lines matched", None
    
    # Calculate match info (convert to 1-indexed for human readability)
    actual_line = first_match_src + 1
    estimated_line = hunk.line_number
    offset = actual_line - estimated_line
    match_info = {
        "estimated_line": estimated_line,
        "actual_line": actual_line,
        "offset": offset,
        "matched_range": f"{first_match_src + 1}-{last_match_src + 1}",
    }
    
    # Build new content:
    # 1. Keep lines before first match
    # 2. Process alignment (keeping/deleting/inserting lines)
    # 3. Keep lines after last match
    new_lines: List[str] = list(source_lines[:first_match_src])
    
    for src_idx, patch_idx in alignment:
        if src_idx is not None:
            # We have a source line
            if patch_idx is not None and hunk.elines[patch_idx][0] == '-':
                # Patch says to delete this line - skip it
                continue
            # Keep the original source line
            new_lines.append(source_lines[src_idx])
        elif patch_idx is not None:
            # No source line matched, but we have a patch line
            edit_type, content = hunk.elines[patch_idx]
            if edit_type == '+':
                # This is a new line to add
                new_lines.append(content)
    
    # Add remaining source lines after the match
    new_lines.extend(source_lines[last_match_src + 1:])
    
    return new_lines, None, match_info


def fuzzy_patch(
    source: str,
    patch: str,
    file_path: str = "file",
) -> FuzzyPatchResult:
    """
    Apply a unified diff patch using fuzzy matching.
    
    This function:
    1. Parses the patch into hunks
    2. For each hunk, uses Smith-Waterman alignment to find where
       the context lines best match in the source
    3. Applies the edits at the matched location
    
    Args:
        source: Original source file content
        patch: Unified diff patch
        file_path: Path for error messages
        
    Returns:
        FuzzyPatchResult with success status and new content or error
    """
    logger.debug(f"Applying fuzzy patch to {file_path}")
    
    # Parse hunks
    hunks = parse_hunks(file_path, patch)
    if not hunks:
        return FuzzyPatchResult(
            success=False,
            error=FuzzyPatchError("No hunks found in patch"),
        )
    
    logger.debug(f"Parsed {len(hunks)} hunk(s)")
    
    # Apply each hunk in sequence
    current_lines = source.splitlines()
    all_matches: List[Tuple[Optional[int], Optional[int]]] = []
    match_details: List[dict] = []
    
    for i, hunk in enumerate(hunks):
        logger.debug(
            f"Applying hunk {i + 1}/{len(hunks)} "
            f"(estimated line {hunk.line_number}, {len(hunk.elines)} edit lines)"
        )
        
        new_lines, error, match_info = apply_hunk(current_lines, hunk)
        
        if error:
            return FuzzyPatchResult(
                success=False,
                error=FuzzyPatchError(
                    f"Failed to apply hunk {i + 1}: {error}",
                    extra={"hunk_index": i, "estimated_line": hunk.line_number},
                ),
            )
        
        # Log match details if line numbers differed
        if match_info:
            match_details.append(match_info)
            offset = match_info.get("offset", 0)
            if offset != 0:
                logger.info(
                    f"Fuzzy match: patch line {match_info['estimated_line']} → "
                    f"actual line {match_info['actual_line']} (offset: {'+' if offset > 0 else ''}{offset})"
                )
            else:
                logger.debug(f"Exact match at line {match_info['actual_line']}")
        
        current_lines = new_lines
    
    # Reconstruct file content
    new_content = '\n'.join(current_lines)
    if source.endswith('\n') and not new_content.endswith('\n'):
        new_content += '\n'
    
    return FuzzyPatchResult(
        success=True,
        new_content=new_content,
        matched_lines=all_matches,
    )


# ==============================================================================
# Convenience wrapper
# ==============================================================================

def apply_patch_fuzzy(
    file_path: Path,
    patch: str,
) -> Tuple[bool, str]:
    """
    Apply a patch to a file using fuzzy matching.
    
    Args:
        file_path: Path to the file to patch
        patch: Unified diff patch content
        
    Returns:
        (success, message) tuple
    """
    if not file_path.exists():
        return False, f"File not found: {file_path}"
    
    source = file_path.read_text()
    result = fuzzy_patch(source, patch, str(file_path.name))
    
    if result.success:
        file_path.write_text(result.new_content)
        return True, "Patch applied successfully"
    else:
        error_msg = result.error.message if result.error else "Unknown error"
        return False, f"Patch failed: {error_msg}"

