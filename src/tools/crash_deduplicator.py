"""
Crash Deduplication for the mini CRS.

Provides stack trace-based deduplication of fuzzer crashes.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from ..storage.models import FuzzCrash


@dataclass()
class CrashSignature:
    """
    A unique signature for a crash based on its stack trace.
    
    The signature is derived from the top N stack frames, extracting:
    - Function name
    - Source file
    - Line number (optional)
    """
    
    error_type: str  # e.g., "heap-use-after-free", "SEGV"
    frames: tuple[str, ...]  # Top N frames as strings
    signature_hash: str  # SHA1 hash for quick comparison
    
    @classmethod
    def from_stack_trace(
        cls, stack_trace: str, num_frames: int = 3
    ) -> "CrashSignature":
        """
        Extract a crash signature from a stack trace.
        
        Args:
            stack_trace: Full stack trace from sanitizer
            num_frames: Number of top frames to use for signature
            
        Returns:
            CrashSignature instance
        """
        error_type = cls._extract_error_type(stack_trace)
        frames = cls._extract_frames(stack_trace, num_frames)
        
        # Create hash from error type + frames
        sig_str = f"{error_type}|{'|'.join(frames)}"
        sig_hash = hashlib.sha1(sig_str.encode()).hexdigest()[:16]
        
        return cls(
            error_type=error_type,
            frames=tuple(frames),
            signature_hash=sig_hash,
        )
    
    @staticmethod
    def _extract_error_type(stack_trace: str) -> str:
        """Extract error type from sanitizer output."""
        # Match patterns like "ERROR: AddressSanitizer: heap-use-after-free"
        match = re.search(r"ERROR:\s*\w*Sanitizer:\s*([^\s]+)", stack_trace)
        if match:
            return match.group(1)
        
        # Match signal patterns
        if "SEGV" in stack_trace or "SIGSEGV" in stack_trace:
            return "SEGV"
        if "SIGABRT" in stack_trace:
            return "SIGABRT"
        
        return "unknown"
    
    @staticmethod
    def _extract_frames(stack_trace: str, num_frames: int) -> list[str]:
        """
        Extract top N stack frames from stack trace.
        
        Returns frames in format: "function@file:line" or "function@file"
        Only parses the main stack trace, not "freed by" or "previously allocated" sections.
        """
        frames: list[str] = []
        in_main_trace = False
        
        for line in stack_trace.split("\n"):
            # Start of main trace (after ERROR: line)
            if "ERROR:" in line and "Sanitizer" in line:
                in_main_trace = True
                continue
            
            # Stop at secondary sections
            if in_main_trace and any(marker in line.lower() for marker in [
                "freed by thread", "previously allocated", "is located", "summary:"
            ]):
                break
            
            if not in_main_trace:
                continue
            
            # Match frame patterns like:
            # #0 0x... in function_name file.c:123
            # #1 0x... in function_name (lib.so+0x...)
            match = re.search(
                r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(.+)",
                line,
                re.IGNORECASE,
            )
            if match:
                func_name = match.group(1)
                location = match.group(2).strip()
                
                # Skip internal frames (fuzzer, asan runtime)
                if _is_internal_frame(func_name, location):
                    continue
                
                # Extract file:line from location
                file_line = _extract_file_line(location)
                if file_line:
                    frames.append(f"{func_name}@{file_line}")
                else:
                    frames.append(func_name)
                
                if len(frames) >= num_frames:
                    break
        
        return frames
    
    def __hash__(self) -> int:
        return hash(self.signature_hash)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CrashSignature):
            return False
        return self.signature_hash == other.signature_hash


def _is_internal_frame(func_name: str, location: str) -> bool:
    """Check if a frame is from internal/runtime code."""
    func_lower = func_name.lower()
    loc_lower = location.lower()
    
    # Exact function name matches (runtime/library functions)
    internal_funcs = {
        "printf", "sprintf", "fprintf", "snprintf", "vprintf",
        "malloc", "calloc", "realloc", "free",
        "operator new", "operator delete",
        "__libc_start_main", "_start", "start",
        "main",  # libFuzzer's main only
    }
    
    # Check for exact matches (but not substring)
    base_func = func_lower.split("(")[0].strip()
    if base_func in internal_funcs:
        return True
    
    # Pattern matches for fuzzer/sanitizer internals
    internal_patterns = [
        "fuzzer::",
        "fuzzer::fuzzer",
        "sanitizer",
        "asan_",
        "__asan",
        "__ubsan",
        "__libc",
        "dyld",
        "fuzzermain",
        "fuzzerloop",
        "fuzzerdriver",
        "libclang_rt",
        "printf_common",
        "llvmfuzzertestoneinput",  # The fuzzer harness entry point
    ]
    
    combined = f"{func_lower} {loc_lower}"
    return any(p in combined for p in internal_patterns)


def _extract_file_line(location: str) -> str | None:
    """Extract file:line from location string."""
    # Match "file.c:123" or "file.c:123:45"
    match = re.search(r"([^/\s]+\.[ch](?:pp|xx)?):(\d+)", location, re.IGNORECASE)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    
    # Match just filename
    match = re.search(r"([^/\s]+\.[ch](?:pp|xx)?)", location, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None


@dataclass()
class CrashCluster:
    """A group of crashes with the same signature."""
    
    signature: CrashSignature
    crashes: list[FuzzCrash] = field(default_factory=list)
    
    @property
    def representative(self) -> FuzzCrash | None:
        """Get a representative crash (smallest input)."""
        if not self.crashes:
            return None
        return min(self.crashes, key=lambda c: c.input_size)
    
    @property
    def count(self) -> int:
        return len(self.crashes)


class CrashDeduplicator:
    """
    Deduplicates crashes based on their stack traces.
    
    Usage:
        dedup = CrashDeduplicator()
        clusters = dedup.deduplicate(crashes)
        unique_crashes = dedup.get_unique_crashes(crashes)
    """
    
    def __init__(self, num_frames: int = 3) -> None:
        """
        Args:
            num_frames: Number of stack frames to use for signature
        """
        self.num_frames = num_frames
    
    def get_signature(self, crash: FuzzCrash) -> CrashSignature | None:
        """Get signature for a crash."""
        if not crash.stack_trace:
            return None
        return CrashSignature.from_stack_trace(
            crash.stack_trace, self.num_frames
        )
    
    def deduplicate(
        self, crashes: Sequence[FuzzCrash]
    ) -> dict[str, CrashCluster]:
        """
        Group crashes by their signature.
        
        Args:
            crashes: List of crashes to deduplicate
            
        Returns:
            Dict mapping signature hash to CrashCluster
        """
        clusters: dict[str, CrashCluster] = {}
        
        for crash in crashes:
            sig = self.get_signature(crash)
            if sig is None:
                # No stack trace - use dedup_token as fallback
                sig_hash = f"no_trace_{crash.dedup_token}"
                if sig_hash not in clusters:
                    clusters[sig_hash] = CrashCluster(
                        signature=CrashSignature(
                            error_type="unknown",
                            frames=(),
                            signature_hash=sig_hash,
                        )
                    )
                clusters[sig_hash].crashes.append(crash)
            else:
                if sig.signature_hash not in clusters:
                    clusters[sig.signature_hash] = CrashCluster(signature=sig)
                clusters[sig.signature_hash].crashes.append(crash)
        
        return clusters
    
    def get_unique_crashes(
        self, crashes: Sequence[FuzzCrash]
    ) -> list[FuzzCrash]:
        """
        Get one representative crash per unique signature.
        
        Args:
            crashes: List of crashes to deduplicate
            
        Returns:
            List of unique crashes (smallest input per cluster)
        """
        clusters = self.deduplicate(crashes)
        unique: list[FuzzCrash] = []
        
        for cluster in clusters.values():
            rep = cluster.representative
            if rep:
                unique.append(rep)
        
        return unique
    
    def get_dedup_summary(
        self, crashes: Sequence[FuzzCrash]
    ) -> dict:
        """
        Get a summary of deduplication results.
        
        Returns:
            Dict with stats and cluster info
        """
        clusters = self.deduplicate(crashes)
        
        return {
            "total_crashes": len(crashes),
            "unique_signatures": len(clusters),
            "reduction_ratio": 1 - (len(clusters) / len(crashes)) if crashes else 0,
            "clusters": [
                {
                    "signature_hash": sig_hash,
                    "error_type": cluster.signature.error_type,
                    "frames": list(cluster.signature.frames),
                    "crash_count": cluster.count,
                    "representative_id": cluster.representative.crash_id if cluster.representative else None,
                }
                for sig_hash, cluster in sorted(
                    clusters.items(),
                    key=lambda x: x[1].count,
                    reverse=True,
                )
            ],
        }

