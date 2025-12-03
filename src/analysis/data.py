"""
Data structures for source code analysis.

These structures hold parsed source code elements (functions, files)
with metadata needed for per-function LLM analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Threshold for "small" functions that could be clubbed together in Phase 2
SMALL_FUNCTION_THRESHOLD = 10  # lines


@dataclass(frozen=True)
class SourceRange:
    """
    A byte range within a source file.
    
    Used for precise slicing of source code without re-reading the file.
    """
    start_byte: int
    end_byte: int
    
    @property
    def length(self) -> int:
        return self.end_byte - self.start_byte
    
    def slice(self, source: str | bytes) -> str | bytes:
        """Extract the content from source using this range."""
        return source[self.start_byte:self.end_byte]


@dataclass
class SourceFunction:
    """
    A parsed function from C source code.
    
    Contains all metadata needed for per-function LLM analysis.
    
    Attributes:
        name: Function name (e.g., "process_packet")
        file_path: Relative path to source file (e.g., "src/vuln.c")
        start_line: 1-indexed line number where function starts
        end_line: 1-indexed line number where function ends
        signature: Function signature (return type + name + params)
        body: Full function body including signature and braces
        byte_range: Byte offsets for precise slicing
        is_small: True if function is below SMALL_FUNCTION_THRESHOLD lines
                  (useful for Phase 2 clubbing consideration)
    """
    name: str
    file_path: str
    start_line: int
    end_line: int
    signature: str
    body: str
    byte_range: SourceRange
    is_small: bool = field(default=False)
    
    @property
    def line_count(self) -> int:
        """Number of lines in the function."""
        return self.end_line - self.start_line + 1
    
    @property
    def finding_id_prefix(self) -> str:
        """Prefix for finding IDs referencing this function."""
        return f"{self.file_path}:{self.name}"
    
    def __post_init__(self) -> None:
        # Auto-compute is_small based on line count
        object.__setattr__(
            self, 
            "is_small", 
            self.line_count < SMALL_FUNCTION_THRESHOLD
        )


@dataclass
class ParsedFile:
    """
    A source file with all its parsed functions.
    
    Attributes:
        path: File path (relative or absolute)
        source: Full source code as string
        functions: List of parsed functions
        parse_errors: Any errors encountered during parsing
        top_level_code: Code outside functions (globals, includes)
                        Stored for completeness but usually not analyzed.
    """
    path: str
    source: str
    functions: list[SourceFunction] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    top_level_code: Optional[str] = None
    
    @property
    def function_count(self) -> int:
        return len(self.functions)
    
    @property
    def small_function_count(self) -> int:
        """Count of functions below the small threshold."""
        return sum(1 for f in self.functions if f.is_small)
    
    @property
    def total_lines(self) -> int:
        """Total lines covered by functions."""
        return sum(f.line_count for f in self.functions)
    
    def get_function_by_name(self, name: str) -> Optional[SourceFunction]:
        """Find a function by name."""
        for func in self.functions:
            if func.name == name:
                return func
        return None
    
    def get_function_at_line(self, line: int) -> Optional[SourceFunction]:
        """Find the function containing a specific line number."""
        for func in self.functions:
            if func.start_line <= line <= func.end_line:
                return func
        return None
    
    def get_functions_in_range(
        self, start_line: int, end_line: int
    ) -> list[SourceFunction]:
        """Get all functions that overlap with a line range."""
        result = []
        for func in self.functions:
            # Check for any overlap
            if func.start_line <= end_line and func.end_line >= start_line:
                result.append(func)
        return result
    
    def get_clubbable_groups(
        self, max_combined_lines: int = 50
    ) -> list[list[SourceFunction]]:
        """
        Group small adjacent functions for potential clubbing (Phase 2).
        
        Returns groups of small functions that are adjacent in the file
        and whose combined line count is below max_combined_lines.
        
        Note: This is a Phase 2 feature. Currently just identifies groups
        but doesn't actually combine them.
        """
        groups: list[list[SourceFunction]] = []
        current_group: list[SourceFunction] = []
        current_lines = 0
        last_end_line = -1
        
        for func in sorted(self.functions, key=lambda f: f.start_line):
            if not func.is_small:
                # Non-small function breaks the group
                if current_group:
                    groups.append(current_group)
                current_group = []
                current_lines = 0
                last_end_line = func.end_line
                continue
            
            # Check if this function is adjacent (within 5 lines of previous)
            is_adjacent = (
                last_end_line < 0 or 
                func.start_line - last_end_line <= 5
            )
            
            can_combine = (
                is_adjacent and 
                current_lines + func.line_count <= max_combined_lines
            )
            
            if can_combine:
                current_group.append(func)
                current_lines += func.line_count
            else:
                # Start new group
                if current_group:
                    groups.append(current_group)
                current_group = [func]
                current_lines = func.line_count
            
            last_end_line = func.end_line
        
        # Don't forget the last group
        if current_group:
            groups.append(current_group)
        
        # Only return groups with 2+ functions (actual clubbing opportunities)
        return [g for g in groups if len(g) >= 2]

