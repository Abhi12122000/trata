"""
Analysis module for AST parsing and source code analysis.

This module provides tree-sitter based parsing for C source files,
extracting function definitions for per-function LLM analysis.
"""

from .data import SourceFunction, ParsedFile, SourceRange
from .c_parser import CParser, parse_c_file

__all__ = [
    "SourceFunction",
    "ParsedFile", 
    "SourceRange",
    "CParser",
    "parse_c_file",
]

