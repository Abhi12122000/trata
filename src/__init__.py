"""
Mini CRS package entrypoint.

The top-level modules under `trata/src` compose the agentic orchestration,
pipelines, and tool integrations needed to analyze a single OSS-Fuzz target.
"""

from .config import TargetProjectConfig, RuntimeConfig
from .orchestration.main import MiniCRSOrchestrator

__all__ = [
    "MiniCRSOrchestrator",
    "RuntimeConfig",
    "TargetProjectConfig",
]

