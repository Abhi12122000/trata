"""
Corpus Manager for fuzzing seeds and crashes.

Manages the fuzzing corpus (seeds) and crash storage with deduplication.
Designed for future LLM integration via callbacks.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Literal, Sequence

from ..storage.models import FuzzCrash, FuzzSeed


# Type aliases for callbacks (for future LLM integration)
SeedCallback = Callable[[FuzzSeed], Awaitable[None]]
CrashCallback = Callable[[FuzzCrash], Awaitable[None]]


@dataclass()
class CorpusManager:
    """
    Manages fuzzing corpus (seeds) and crashes.

    Directory structure:
        corpus_dir/
            seeds/           # All seed files (named by SHA1)
            crashes/         # Crash inputs organized by dedup token
                <dedup_token>/
                    <crash_id>
            initial/         # Initial seeds (copied to seeds/ on init)

    Callbacks:
        on_seed_found: Called when a new seed is discovered
        on_crash_found: Called when a new crash is discovered
    """

    corpus_dir: Path
    harness_name: str
    max_crashes_per_bucket: int = 5

    # Internal state (initialized in __post_init__)
    _seeds: set[str] = field(default_factory=set)
    _crashes: dict[str, list[str]] = field(default_factory=dict)  # dedup -> [crash_ids]
    _seed_callbacks: list[SeedCallback] = field(default_factory=list)
    _crash_callbacks: list[CrashCallback] = field(default_factory=list)
    _lock: asyncio.Lock | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Initialize the lock lazily to avoid event loop issues."""
        # Lock will be created when first needed in async context
        pass

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the async lock."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def seeds_dir(self) -> Path:
        return self.corpus_dir / "seeds"

    @property
    def crashes_dir(self) -> Path:
        return self.corpus_dir / "crashes"

    @property
    def initial_dir(self) -> Path:
        return self.corpus_dir / "initial"

    @property
    def seed_count(self) -> int:
        return len(self._seeds)

    @property
    def crash_count(self) -> int:
        return sum(len(v) for v in self._crashes.values())

    @property
    def known_seeds(self) -> frozenset[str]:
        return frozenset(self._seeds)

    @property
    def known_crashes(self) -> frozenset[str]:
        return frozenset(c for crashes in self._crashes.values() for c in crashes)

    async def init(self) -> None:
        """Initialize corpus directories and load existing state."""
        self.seeds_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        self.initial_dir.mkdir(parents=True, exist_ok=True)

        # Load existing seeds
        for seed_file in self.seeds_dir.iterdir():
            if seed_file.is_file():
                self._seeds.add(seed_file.name)

        # Load existing crashes
        for bucket_dir in self.crashes_dir.iterdir():
            if bucket_dir.is_dir():
                dedup_token = bucket_dir.name
                self._crashes[dedup_token] = []
                for crash_file in bucket_dir.iterdir():
                    if crash_file.is_file():
                        self._crashes[dedup_token].append(crash_file.name)

        # Copy initial seeds to seeds directory
        for initial_seed in self.initial_dir.iterdir():
            if initial_seed.is_file():
                content = initial_seed.read_bytes()
                await self.add_seed(content, source="initial")

    def add_seed_callback(self, callback: SeedCallback) -> None:
        """Register a callback for new seeds (for LLM integration)."""
        self._seed_callbacks.append(callback)

    def add_crash_callback(self, callback: CrashCallback) -> None:
        """Register a callback for new crashes (for LLM integration)."""
        self._crash_callbacks.append(callback)

    async def add_seed(
        self,
        data: bytes,
        source: Literal["initial", "fuzzer", "llm", "corpus_match"] = "fuzzer",
        seed_id: str | None = None,
    ) -> FuzzSeed | None:
        """
        Add a seed to the corpus.

        Returns the FuzzSeed if it's new, None if it already exists.
        """
        if seed_id is None:
            seed_id = hashlib.sha1(data).hexdigest()

        async with self._get_lock():
            if seed_id in self._seeds:
                return None

            seed_path = self.seeds_dir / seed_id
            seed_path.write_bytes(data)
            self._seeds.add(seed_id)

        seed = FuzzSeed(
            seed_id=seed_id,
            path=seed_path,
            size=len(data),
            source=source,
        )

        # Fire callbacks
        for callback in self._seed_callbacks:
            try:
                await callback(seed)
            except Exception:
                pass  # Don't let callback errors break fuzzing

        return seed

    async def add_seeds_bulk(
        self,
        seeds: Sequence[tuple[bytes, str | None]],
        source: Literal["initial", "fuzzer", "llm", "corpus_match"] = "fuzzer",
    ) -> list[FuzzSeed]:
        """Add multiple seeds efficiently. Returns list of new seeds."""
        new_seeds: list[FuzzSeed] = []

        for data, seed_id in seeds:
            seed = await self.add_seed(data, source=source, seed_id=seed_id)
            if seed:
                new_seeds.append(seed)

        return new_seeds

    async def add_crash(
        self,
        data: bytes,
        dedup_token: str,
        harness: str,
        stack_trace: str = "",
        signal: str = "",
        crash_id: str | None = None,
    ) -> FuzzCrash | None:
        """
        Add a crash to the corpus.

        Returns the FuzzCrash if it's new, None if already exists or bucket is full.
        """
        if crash_id is None:
            crash_id = hashlib.sha1(data).hexdigest()

        # Sanitize dedup token for filesystem
        safe_dedup = self._sanitize_dedup_token(dedup_token)

        async with self._get_lock():
            # Check if crash already exists
            if safe_dedup in self._crashes:
                if crash_id in self._crashes[safe_dedup]:
                    return None
                if len(self._crashes[safe_dedup]) >= self.max_crashes_per_bucket:
                    return None  # Bucket full
            else:
                self._crashes[safe_dedup] = []

            # Write crash file
            bucket_dir = self.crashes_dir / safe_dedup
            bucket_dir.mkdir(exist_ok=True)
            crash_path = bucket_dir / crash_id
            crash_path.write_bytes(data)
            self._crashes[safe_dedup].append(crash_id)

        crash = FuzzCrash(
            crash_id=crash_id,
            input_path=crash_path,
            input_size=len(data),
            dedup_token=dedup_token,
            harness=harness,
            timestamp=datetime.now(timezone.utc).isoformat(),
            stack_trace=stack_trace,
            signal=signal,
        )

        # Fire callbacks
        for callback in self._crash_callbacks:
            try:
                await callback(crash)
            except Exception:
                pass

        return crash

    def get_seeds(self, max_count: int | None = None) -> dict[str, bytes]:
        """Get seeds from the corpus."""
        result: dict[str, bytes] = {}
        for seed_id in self._seeds:
            if max_count and len(result) >= max_count:
                break
            seed_path = self.seeds_dir / seed_id
            if seed_path.exists():
                result[seed_id] = seed_path.read_bytes()
        return result

    def get_crashes(self) -> list[FuzzCrash]:
        """Get all crashes."""
        crashes: list[FuzzCrash] = []
        for dedup_token, crash_ids in self._crashes.items():
            for crash_id in crash_ids:
                crash_path = self.crashes_dir / dedup_token / crash_id
                if crash_path.exists():
                    crashes.append(
                        FuzzCrash(
                            crash_id=crash_id,
                            input_path=crash_path,
                            input_size=crash_path.stat().st_size,
                            dedup_token=dedup_token,
                            harness=self.harness_name,
                            timestamp="",  # Unknown for loaded crashes
                        )
                    )
        return crashes

    def copy_seeds_to(self, target_dir: Path) -> int:
        """Copy all seeds to a target directory (for fuzzer input)."""
        target_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for seed_id in self._seeds:
            src = self.seeds_dir / seed_id
            dst = target_dir / seed_id
            if src.exists() and not dst.exists():
                shutil.copy2(src, dst)
                count += 1
        return count

    def sync_seeds_from(self, source_dir: Path) -> list[str]:
        """
        Sync new seeds from a directory (after fuzzer run).

        Returns list of new seed IDs.
        """
        new_seeds: list[str] = []
        for seed_file in source_dir.iterdir():
            if seed_file.is_file():
                seed_id = seed_file.name
                if seed_id not in self._seeds:
                    content = seed_file.read_bytes()
                    dst = self.seeds_dir / seed_id
                    dst.write_bytes(content)
                    self._seeds.add(seed_id)
                    new_seeds.append(seed_id)
        return new_seeds

    @staticmethod
    def _sanitize_dedup_token(token: str) -> str:
        """Make dedup token safe for filesystem."""
        if not token:
            return "UNKNOWN"
        # If token has special chars or is too long, hash it
        if len(token) > 64 or any(c in token for c in r'<>:"/\|?*'):
            return hashlib.sha1(token.encode()).hexdigest()
        return token

