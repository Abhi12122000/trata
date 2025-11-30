"""
Unit tests for the fuzzing pipeline components.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

# Ensure trata is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from trata.src.tools.corpus_manager import CorpusManager
from trata.src.storage.models import FuzzingConfig


def test_corpus_manager_add_seed():
    """Test adding seeds to corpus manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir)
        manager = CorpusManager(
            corpus_dir=corpus_dir,
            harness_name="test_harness",
        )

        # Initialize
        asyncio.run(manager.init())

        # Add a seed
        seed_data = b"test seed data"
        seed = asyncio.run(manager.add_seed(seed_data, source="initial"))

        assert seed is not None
        assert seed.size == len(seed_data)
        assert seed.source == "initial"
        assert manager.seed_count == 1

        # Adding same seed again should return None
        duplicate = asyncio.run(manager.add_seed(seed_data, source="fuzzer"))
        assert duplicate is None
        assert manager.seed_count == 1


def test_corpus_manager_add_crash():
    """Test adding crashes to corpus manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir)
        manager = CorpusManager(
            corpus_dir=corpus_dir,
            harness_name="test_harness",
            max_crashes_per_bucket=3,
        )

        asyncio.run(manager.init())

        # Add a crash
        crash_data = b"crash input"
        crash = asyncio.run(
            manager.add_crash(
                data=crash_data,
                dedup_token="SIGSEGV_stack_hash",
                harness="test_harness",
                signal="SIGSEGV",
            )
        )

        assert crash is not None
        assert crash.input_size == len(crash_data)
        assert crash.dedup_token == "SIGSEGV_stack_hash"
        assert manager.crash_count == 1


def test_corpus_manager_crash_bucket_limit():
    """Test that crash bucket limits are enforced."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir)
        manager = CorpusManager(
            corpus_dir=corpus_dir,
            harness_name="test_harness",
            max_crashes_per_bucket=2,
        )

        asyncio.run(manager.init())

        # Add crashes with same dedup token
        for i in range(5):
            crash = asyncio.run(
                manager.add_crash(
                    data=f"crash_{i}".encode(),
                    dedup_token="same_token",
                    harness="test_harness",
                )
            )
            if i < 2:
                assert crash is not None, f"Crash {i} should be added"
            else:
                assert crash is None, f"Crash {i} should be rejected (bucket full)"

        assert manager.crash_count == 2


def test_corpus_manager_seed_sync():
    """Test syncing seeds from external directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir) / "corpus"
        external_dir = Path(tmpdir) / "external"
        external_dir.mkdir()

        manager = CorpusManager(
            corpus_dir=corpus_dir,
            harness_name="test_harness",
        )

        asyncio.run(manager.init())

        # Create some seeds in external directory
        (external_dir / "seed1").write_bytes(b"seed1")
        (external_dir / "seed2").write_bytes(b"seed2")

        # Sync from external
        new_seeds = manager.sync_seeds_from(external_dir)

        assert len(new_seeds) == 2
        assert manager.seed_count == 2


def test_fuzzing_config_defaults():
    """Test FuzzingConfig default values."""
    config = FuzzingConfig()

    assert config.timeout_seconds == 60
    assert config.max_total_time == 300
    assert config.workers == 1
    assert config.detect_leaks is False
    assert config.max_crashes_per_bucket == 5


def test_corpus_manager_get_seeds():
    """Test retrieving seeds from corpus."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir)
        manager = CorpusManager(
            corpus_dir=corpus_dir,
            harness_name="test_harness",
        )

        asyncio.run(manager.init())

        # Add some seeds
        asyncio.run(manager.add_seed(b"seed1", source="initial"))
        asyncio.run(manager.add_seed(b"seed2", source="initial"))
        asyncio.run(manager.add_seed(b"seed3", source="initial"))

        # Get all seeds
        seeds = manager.get_seeds()
        assert len(seeds) == 3

        # Get limited seeds
        limited = manager.get_seeds(max_count=2)
        assert len(limited) == 2


def test_find_fuzzer_binary():
    """Test that _find_fuzzer_binary finds common fuzzer names."""
    from trata.src.pipelines.patching import PatchingPipeline
    from trata.src.config import RuntimeConfig
    from trata.src.storage.local_store import LocalRunStore
    from unittest.mock import MagicMock
    import os
    
    with tempfile.TemporaryDirectory() as tmpdir:
        source_dir = Path(tmpdir)
        build_dir = source_dir / "build"
        build_dir.mkdir()
        
        runtime = RuntimeConfig()
        mock_store = MagicMock()
        mock_llm = MagicMock()
        
        pipeline = PatchingPipeline(runtime, mock_store, mock_llm)
        
        # Test with vuln_fuzzer
        (build_dir / "vuln_fuzzer").write_text("#!/bin/bash\necho test")
        os.chmod(build_dir / "vuln_fuzzer", 0o755)
        
        found = pipeline._find_fuzzer_binary(source_dir)
        assert found is not None
        assert "vuln_fuzzer" in str(found)
        
        # Test with packet_fuzzer
        (build_dir / "vuln_fuzzer").unlink()
        (build_dir / "packet_fuzzer").write_text("#!/bin/bash\necho test")
        os.chmod(build_dir / "packet_fuzzer", 0o755)
        
        found = pipeline._find_fuzzer_binary(source_dir)
        assert found is not None
        assert "packet_fuzzer" in str(found)
        
        # Test with generic fuzzer name
        (build_dir / "packet_fuzzer").unlink()
        (build_dir / "fuzz_target").write_text("#!/bin/bash\necho test")
        os.chmod(build_dir / "fuzz_target", 0o755)
        
        found = pipeline._find_fuzzer_binary(source_dir)
        assert found is not None
        assert "fuzz_target" in str(found)


def test_find_fuzzer_binary_glob_patterns():
    """Test that fuzzer binary search uses glob patterns."""
    from trata.src.pipelines.patching import PatchingPipeline
    from trata.src.config import RuntimeConfig
    from unittest.mock import MagicMock
    import os
    
    with tempfile.TemporaryDirectory() as tmpdir:
        source_dir = Path(tmpdir)
        build_dir = source_dir / "build"
        build_dir.mkdir()
        
        runtime = RuntimeConfig()
        mock_store = MagicMock()
        mock_llm = MagicMock()
        
        pipeline = PatchingPipeline(runtime, mock_store, mock_llm)
        
        # Test with any name containing "fuzzer"
        (build_dir / "my_custom_fuzzer_v2").write_text("#!/bin/bash\necho test")
        os.chmod(build_dir / "my_custom_fuzzer_v2", 0o755)
        
        found = pipeline._find_fuzzer_binary(source_dir)
        assert found is not None
        assert "fuzzer" in str(found)


if __name__ == "__main__":
    # Run tests
    test_corpus_manager_add_seed()
    print("✓ test_corpus_manager_add_seed passed")

    test_corpus_manager_add_crash()
    print("✓ test_corpus_manager_add_crash passed")

    test_corpus_manager_crash_bucket_limit()
    print("✓ test_corpus_manager_crash_bucket_limit passed")

    test_corpus_manager_seed_sync()
    print("✓ test_corpus_manager_seed_sync passed")

    test_fuzzing_config_defaults()
    print("✓ test_fuzzing_config_defaults passed")

    test_corpus_manager_get_seeds()
    print("✓ test_corpus_manager_get_seeds passed")
    
    test_find_fuzzer_binary()
    print("✓ test_find_fuzzer_binary passed")
    
    test_find_fuzzer_binary_glob_patterns()
    print("✓ test_find_fuzzer_binary_glob_patterns passed")

    print("\nAll fuzzing tests passed!")

