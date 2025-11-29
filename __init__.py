"""
Top-level package marker for the mini CRS code.

This allows tests (e.g. `pytest trata/tests/...`) to import modules such as
`trata.src.tools.llm_client`.
"""

from .src import *  # re-export for convenience

