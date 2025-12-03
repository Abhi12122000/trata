"""
C source code parser using tree-sitter.

Extracts function definitions from C source files for per-function
LLM analysis. Falls back to regex-based parsing if tree-sitter
is not available.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from .data import SourceFunction, ParsedFile, SourceRange

logger = logging.getLogger(__name__)

# Try to import tree-sitter, fall back gracefully if not available
_TREE_SITTER_AVAILABLE = False
_tree_sitter = None
_tree_sitter_c = None
_parser = None
_lang = None
_query = None

try:
    import tree_sitter as _tree_sitter
    import tree_sitter_c as _tree_sitter_c
    
    _lang = _tree_sitter.Language(_tree_sitter_c.language())
    _parser = _tree_sitter.Parser(_lang)
    
    # Query to extract function definitions
    # This query handles:
    # - Regular functions: void foo(void)
    # - Single pointer returns: int *foo(void)
    # - Double pointer returns: char **foo(void) 
    # - Function pointer returns: int (*foo(void))(int)
    # Note: Uses multiple patterns to cover various declarator nesting
    _query = _lang.query("""
    (function_definition
      body: (compound_statement) @func.body
    ) @func.def
    """)
    
    _TREE_SITTER_AVAILABLE = True
    logger.debug("tree-sitter initialized successfully")
    
except ImportError as e:
    logger.warning(
        f"tree-sitter not available ({e}). "
        "Falling back to regex-based parsing. "
        "Install with: pip install tree-sitter tree-sitter-c"
    )
except Exception as e:
    logger.warning(f"tree-sitter initialization failed: {e}. Using fallback parser.")


def is_tree_sitter_available() -> bool:
    """Check if tree-sitter is available for parsing."""
    return _TREE_SITTER_AVAILABLE


class CParser:
    """
    Parser for C source files.
    
    Uses tree-sitter for accurate AST-based parsing when available,
    falls back to regex-based heuristics otherwise.
    """
    
    def __init__(self) -> None:
        self._use_tree_sitter = _TREE_SITTER_AVAILABLE
    
    def _extract_function_name(self, func_def_node) -> Optional[str]:
        """
        Extract function name from a function_definition node.
        
        Handles various declarator nestings:
        - Direct: void foo(void)
        - Pointer: int *foo(void)
        - Double pointer: char **foo(void)
        - Function pointer return: int (*foo(void))(int)
        - Parenthesized: void (foo)(void)
        """
        # Find the declarator child
        declarator = None
        for child in func_def_node.children:
            if child.type == "function_declarator":
                declarator = child
                break
            elif child.type == "pointer_declarator":
                declarator = child
                break
            elif child.type == "parenthesized_declarator":
                declarator = child
                break
        
        if not declarator:
            return None
        
        # Recursively find the identifier (function name)
        return self._find_identifier_in_declarator(declarator)
    
    def _find_identifier_in_declarator(self, node) -> Optional[str]:
        """Recursively find the identifier in nested declarators."""
        if node.type == "identifier":
            return node.text.decode("utf-8") if node.text else None
        
        # Check children for function_declarator or identifier
        for child in node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8") if child.text else None
            elif child.type in ("function_declarator", "pointer_declarator", 
                               "parenthesized_declarator", "array_declarator"):
                result = self._find_identifier_in_declarator(child)
                if result:
                    return result
        
        return None
    
    def parse_file(self, file_path: str | Path, source: Optional[str] = None) -> ParsedFile:
        """
        Parse a C source file and extract all functions.
        
        Args:
            file_path: Path to the source file (for metadata)
            source: Optional source code string. If not provided,
                   the file is read from disk.
        
        Returns:
            ParsedFile containing all extracted functions
        """
        path = Path(file_path)
        path_str = str(path)
        
        # Read source if not provided
        if source is None:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                return ParsedFile(
                    path=path_str,
                    source="",
                    functions=[],
                    parse_errors=[f"File not found: {path_str}"],
                )
            except Exception as e:
                return ParsedFile(
                    path=path_str,
                    source="",
                    functions=[],
                    parse_errors=[f"Error reading file: {e}"],
                )
        
        # Parse using appropriate method
        if self._use_tree_sitter:
            return self._parse_with_tree_sitter(path_str, source)
        else:
            return self._parse_with_regex(path_str, source)
    
    def _parse_with_tree_sitter(self, file_path: str, source: str) -> ParsedFile:
        """Parse using tree-sitter AST."""
        functions: list[SourceFunction] = []
        errors: list[str] = []
        
        try:
            # Parse the source
            source_bytes = source.encode("utf-8")
            tree = _parser.parse(source_bytes)
            
            # Build line index for O(1) line number lookups
            line_starts = [0]
            for i, char in enumerate(source):
                if char == "\n":
                    line_starts.append(i + 1)
            
            def byte_to_line(byte_offset: int) -> int:
                """Convert byte offset to 1-indexed line number."""
                # Binary search for the line
                lo, hi = 0, len(line_starts) - 1
                while lo < hi:
                    mid = (lo + hi + 1) // 2
                    if line_starts[mid] <= byte_offset:
                        lo = mid
                    else:
                        hi = mid - 1
                return lo + 1  # 1-indexed
            
            # Query for function definitions
            matches = _query.matches(tree.root_node)
            
            for pattern_idx, match in matches:
                try:
                    func_def = match.get("func.def")
                    func_body = match.get("func.body")
                    
                    if not func_def:
                        continue
                    
                    # Extract function name by traversing the declarator
                    name = self._extract_function_name(func_def)
                    if not name:
                        continue
                    
                    # Calculate line numbers
                    start_line = byte_to_line(func_def.start_byte)
                    end_line = byte_to_line(func_def.end_byte)
                    
                    # Build signature (everything before the body)
                    if func_body:
                        sig_bytes = source_bytes[func_def.start_byte:func_body.start_byte]
                        signature = sig_bytes.decode("utf-8", errors="replace").strip()
                    else:
                        signature = name
                    
                    # Extract full body
                    body = source[func_def.start_byte:func_def.end_byte]
                    
                    functions.append(SourceFunction(
                        name=name,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        signature=signature,
                        body=body,
                        byte_range=SourceRange(func_def.start_byte, func_def.end_byte),
                    ))
                    
                except Exception as e:
                    errors.append(f"Error parsing function: {e}")
            
            # Sort by start line
            functions.sort(key=lambda f: f.start_line)
            
        except Exception as e:
            errors.append(f"tree-sitter parsing failed: {e}")
            # Fall back to regex
            return self._parse_with_regex(file_path, source)
        
        return ParsedFile(
            path=file_path,
            source=source,
            functions=functions,
            parse_errors=errors,
        )
    
    def _parse_with_regex(self, file_path: str, source: str) -> ParsedFile:
        """
        Fallback regex-based parsing.
        
        Less accurate than tree-sitter but works without dependencies.
        Handles most common C function patterns.
        """
        functions: list[SourceFunction] = []
        errors: list[str] = []
        
        # C keywords that should NOT be matched as function names
        C_KEYWORDS = {
            "if", "else", "for", "while", "do", "switch", "case", "default",
            "return", "break", "continue", "goto", "sizeof", "typedef",
            "struct", "union", "enum", "extern", "register", "auto",
        }
        
        # Regex pattern for C function definitions
        # Matches: return_type function_name(params) { ... }
        # Note: This is a simplified pattern and may miss some edge cases
        func_pattern = re.compile(
            r"""
            ^                           # Start of line
            (?P<signature>
                (?:static\s+)?          # Optional static
                (?:inline\s+)?          # Optional inline
                (?:const\s+)?           # Optional const
                [\w\s\*]+               # Return type (e.g., "void", "int *", "struct foo")
                \s+
                (?P<name>\w+)           # Function name
                \s*
                \([^)]*\)               # Parameters
            )
            \s*
            \{                          # Opening brace
            """,
            re.MULTILINE | re.VERBOSE
        )
        
        for match in func_pattern.finditer(source):
            try:
                name = match.group("name")
                
                # Skip C keywords (if, for, while, etc.)
                if name in C_KEYWORDS:
                    continue
                
                signature = match.group("signature").strip()
                start_byte = match.start()
                
                # Find matching closing brace
                brace_count = 1
                pos = match.end()
                while pos < len(source) and brace_count > 0:
                    if source[pos] == "{":
                        brace_count += 1
                    elif source[pos] == "}":
                        brace_count -= 1
                    pos += 1
                
                if brace_count != 0:
                    errors.append(f"Unmatched braces for function {name}")
                    continue
                
                end_byte = pos
                body = source[start_byte:end_byte]
                
                # Calculate line numbers
                start_line = source[:start_byte].count("\n") + 1
                end_line = source[:end_byte].count("\n") + 1
                
                functions.append(SourceFunction(
                    name=name,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    signature=signature,
                    body=body,
                    byte_range=SourceRange(start_byte, end_byte),
                ))
                
            except Exception as e:
                errors.append(f"Regex parsing error: {e}")
        
        # Sort by start line
        functions.sort(key=lambda f: f.start_line)
        
        if not functions and not errors:
            errors.append("No functions found (regex fallback mode)")
        
        return ParsedFile(
            path=file_path,
            source=source,
            functions=functions,
            parse_errors=errors,
        )


# Module-level convenience function
def parse_c_file(file_path: str | Path, source: Optional[str] = None) -> ParsedFile:
    """
    Parse a C source file and extract all functions.
    
    This is a convenience function that creates a CParser and parses the file.
    
    Args:
        file_path: Path to the source file
        source: Optional source code (reads from file if not provided)
    
    Returns:
        ParsedFile with extracted functions
    
    Example:
        >>> parsed = parse_c_file("src/vuln.c")
        >>> for func in parsed.functions:
        ...     print(f"{func.name}: lines {func.start_line}-{func.end_line}")
        use_after_free_example: lines 18-25
        null_deref_example: lines 30-37
        ...
    """
    parser = CParser()
    return parser.parse_file(file_path, source)

