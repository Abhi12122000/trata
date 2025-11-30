"""Tests for crash deduplication."""

import sys
from pathlib import Path

# Add trata to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from trata.src.storage.models import FuzzCrash
from trata.src.tools.crash_deduplicator import (
    CrashDeduplicator,
    CrashSignature,
    CrashCluster,
    _is_internal_frame,
    _extract_file_line,
)


# Sample stack traces for testing
STACK_TRACE_UAF = """
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x6060000002c0 at pc 0x000102966a60
    #0 0x102966a5c in printf_common(void*, char const*, char*)+0x890 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x22a5c)
    #1 0x102967840 in printf+0x60 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x23840)
    #2 0x1021dcac4 in use_after_free_example vuln.c:24
    #3 0x1021dd048 in LLVMFuzzerTestOneInput vuln_fuzzer.c:30
    #4 0x1021f64cc in fuzzer::Fuzzer::ExecuteCallback FuzzerLoop.cpp:619

0x6060000002c0 is located 0 bytes inside of 64-byte region
freed by thread T0 here:
    #0 0x10107f564 in free+0x74 (libclang_rt.asan_osx_dynamic.dylib)
    #1 0x100a54ab4 in use_after_free_example vuln.c:22

SUMMARY: AddressSanitizer: heap-use-after-free
"""

STACK_TRACE_UAF_SAME = """
==67890==ERROR: AddressSanitizer: heap-use-after-free on address 0x6060000003d0 at pc 0x000102966a60
    #0 0x102966a5c in printf_common(void*, char const*, char*)+0x890 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x22a5c)
    #1 0x102967840 in printf+0x60 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x23840)
    #2 0x1021dcac4 in use_after_free_example vuln.c:24
    #3 0x1021dd048 in LLVMFuzzerTestOneInput vuln_fuzzer.c:30
"""

STACK_TRACE_NULL = """
==11111==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x1021dcaf0 in null_deref_example vuln.c:35
    #1 0x1021dd060 in LLVMFuzzerTestOneInput vuln_fuzzer.c:35
    #2 0x1021f64cc in fuzzer::Fuzzer::ExecuteCallback FuzzerLoop.cpp:619
"""

STACK_TRACE_DOUBLE_FREE = """
==22222==ERROR: AddressSanitizer: attempting double-free on 0x606000000380
    #0 0x10107f564 in free+0x74 (libclang_rt.asan_osx_dynamic.dylib)
    #1 0x1021dcb20 in double_free_example vuln.c:42
    #2 0x1021dd078 in LLVMFuzzerTestOneInput vuln_fuzzer.c:40
"""


def test_signature_from_stack_trace_uaf():
    """Test signature extraction from use-after-free trace."""
    sig = CrashSignature.from_stack_trace(STACK_TRACE_UAF)
    
    assert sig.error_type == "heap-use-after-free"
    assert len(sig.frames) > 0
    # Should have extracted the user code frame (use_after_free_example)
    assert any("use_after_free_example" in f for f in sig.frames)
    assert sig.signature_hash


def test_signature_from_stack_trace_null():
    """Test signature extraction from null dereference trace."""
    sig = CrashSignature.from_stack_trace(STACK_TRACE_NULL)
    
    assert sig.error_type == "SEGV"
    assert len(sig.frames) > 0
    assert any("null_deref_example" in f for f in sig.frames)


def test_signature_equality():
    """Test that same stack traces produce equal signatures."""
    sig1 = CrashSignature.from_stack_trace(STACK_TRACE_UAF)
    sig2 = CrashSignature.from_stack_trace(STACK_TRACE_UAF_SAME)
    
    # Same bug, same signature
    assert sig1 == sig2
    assert sig1.signature_hash == sig2.signature_hash


def test_signature_different_bugs():
    """Test that different bugs produce different signatures."""
    sig_uaf = CrashSignature.from_stack_trace(STACK_TRACE_UAF)
    sig_null = CrashSignature.from_stack_trace(STACK_TRACE_NULL)
    sig_double = CrashSignature.from_stack_trace(STACK_TRACE_DOUBLE_FREE)
    
    assert sig_uaf != sig_null
    assert sig_uaf != sig_double
    assert sig_null != sig_double


def test_is_internal_frame():
    """Test internal frame detection."""
    # Internal/runtime frames should be filtered
    assert _is_internal_frame("fuzzer::Fuzzer::RunOne", "FuzzerLoop.cpp:123")
    assert _is_internal_frame("printf", "stdio.c:100")
    assert _is_internal_frame("printf_common", "libclang_rt.asan_osx_dynamic.dylib")
    assert _is_internal_frame("malloc", "malloc.c:50")
    assert _is_internal_frame("__libc_start_main", "libc.so")
    assert _is_internal_frame("LLVMFuzzerTestOneInput", "harness.c:10")
    
    # User code should NOT be internal (even with similar names)
    assert not _is_internal_frame("use_after_free_example", "vuln.c:24")
    assert not _is_internal_frame("double_free_example", "vuln.c:42")
    assert not _is_internal_frame("process_packet", "vuln.c:55")
    assert not _is_internal_frame("my_malloc_wrapper", "utils.c:100")


def test_extract_file_line():
    """Test file:line extraction."""
    assert _extract_file_line("vuln.c:24") == "vuln.c:24"
    assert _extract_file_line("/path/to/vuln.c:24") == "vuln.c:24"
    assert _extract_file_line("vuln.cpp:123:45") == "vuln.cpp:123"
    assert _extract_file_line("test.h:10") == "test.h:10"
    assert _extract_file_line("(libfoo.so+0x1234)") is None


def test_deduplicator_basic():
    """Test basic deduplication."""
    crashes = [
        FuzzCrash(
            crash_id="crash1",
            input_path=Path("/crashes/crash1"),
            input_size=10,
            dedup_token="token1",
            harness="test",
            timestamp="2024-01-01T00:00:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_UAF,
        ),
        FuzzCrash(
            crash_id="crash2",
            input_path=Path("/crashes/crash2"),
            input_size=5,  # Smaller - should be representative
            dedup_token="token2",
            harness="test",
            timestamp="2024-01-01T00:01:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_UAF_SAME,  # Same bug as crash1
        ),
        FuzzCrash(
            crash_id="crash3",
            input_path=Path("/crashes/crash3"),
            input_size=15,
            dedup_token="token3",
            harness="test",
            timestamp="2024-01-01T00:02:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_NULL,  # Different bug
        ),
    ]
    
    dedup = CrashDeduplicator()
    clusters = dedup.deduplicate(crashes)
    
    # Should have 2 unique clusters (UAF and NULL)
    assert len(clusters) == 2
    
    # Check cluster sizes
    sizes = sorted(c.count for c in clusters.values())
    assert sizes == [1, 2]  # 2 UAF crashes, 1 NULL crash


def test_deduplicator_unique_crashes():
    """Test getting unique crashes."""
    crashes = [
        FuzzCrash(
            crash_id="crash1",
            input_path=Path("/crashes/crash1"),
            input_size=100,
            dedup_token="token1",
            harness="test",
            timestamp="2024-01-01T00:00:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_UAF,
        ),
        FuzzCrash(
            crash_id="crash2",
            input_path=Path("/crashes/crash2"),
            input_size=5,  # Smallest - should be picked
            dedup_token="token2",
            harness="test",
            timestamp="2024-01-01T00:01:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_UAF_SAME,
        ),
        FuzzCrash(
            crash_id="crash3",
            input_path=Path("/crashes/crash3"),
            input_size=50,
            dedup_token="token3",
            harness="test",
            timestamp="2024-01-01T00:02:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_UAF,  # Another duplicate
        ),
    ]
    
    dedup = CrashDeduplicator()
    unique = dedup.get_unique_crashes(crashes)
    
    # Should have 1 unique crash
    assert len(unique) == 1
    # Should pick the smallest input
    assert unique[0].crash_id == "crash2"
    assert unique[0].input_size == 5


def test_deduplicator_no_stack_trace():
    """Test handling crashes without stack traces."""
    crashes = [
        FuzzCrash(
            crash_id="crash1",
            input_path=Path("/crashes/crash1"),
            input_size=10,
            dedup_token="token1",
            harness="test",
            timestamp="2024-01-01T00:00:00",
            signal="SIGSEGV",
            stack_trace="",  # No stack trace
        ),
        FuzzCrash(
            crash_id="crash2",
            input_path=Path("/crashes/crash2"),
            input_size=5,
            dedup_token="token1",  # Same dedup token
            harness="test",
            timestamp="2024-01-01T00:01:00",
            signal="SIGSEGV",
            stack_trace="",  # No stack trace
        ),
    ]
    
    dedup = CrashDeduplicator()
    clusters = dedup.deduplicate(crashes)
    
    # Should use dedup_token as fallback, both in same cluster
    assert len(clusters) == 1
    assert list(clusters.values())[0].count == 2


def test_deduplicator_summary():
    """Test deduplication summary."""
    crashes = [
        FuzzCrash(
            crash_id="crash1",
            input_path=Path("/crashes/crash1"),
            input_size=10,
            dedup_token="token1",
            harness="test",
            timestamp="2024-01-01T00:00:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_UAF,
        ),
        FuzzCrash(
            crash_id="crash2",
            input_path=Path("/crashes/crash2"),
            input_size=5,
            dedup_token="token2",
            harness="test",
            timestamp="2024-01-01T00:01:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_UAF_SAME,
        ),
        FuzzCrash(
            crash_id="crash3",
            input_path=Path("/crashes/crash3"),
            input_size=15,
            dedup_token="token3",
            harness="test",
            timestamp="2024-01-01T00:02:00",
            signal="SIGSEGV",
            stack_trace=STACK_TRACE_NULL,
        ),
    ]
    
    dedup = CrashDeduplicator()
    summary = dedup.get_dedup_summary(crashes)
    
    assert summary["total_crashes"] == 3
    assert summary["unique_signatures"] == 2
    assert 0 < summary["reduction_ratio"] < 1
    assert len(summary["clusters"]) == 2


def test_deduplicator_with_real_data():
    """Test with a larger set of similar crashes."""
    # Simulate many crashes from the same bug
    crashes = []
    for i in range(100):
        crashes.append(
            FuzzCrash(
                crash_id=f"crash{i}",
                input_path=Path(f"/crashes/crash{i}"),
                input_size=i + 1,
                dedup_token=f"token{i}",
                harness="test",
                timestamp="2024-01-01T00:00:00",
                signal="SIGSEGV",
                stack_trace=STACK_TRACE_UAF if i % 3 != 2 else STACK_TRACE_NULL,
            )
        )
    
    dedup = CrashDeduplicator()
    unique = dedup.get_unique_crashes(crashes)
    
    # Should have 2 unique (UAF and NULL)
    assert len(unique) == 2
    
    summary = dedup.get_dedup_summary(crashes)
    assert summary["reduction_ratio"] > 0.9  # 98% reduction


def run_tests():
    """Run all tests."""
    tests = [
        test_signature_from_stack_trace_uaf,
        test_signature_from_stack_trace_null,
        test_signature_equality,
        test_signature_different_bugs,
        test_is_internal_frame,
        test_extract_file_line,
        test_deduplicator_basic,
        test_deduplicator_unique_crashes,
        test_deduplicator_no_stack_trace,
        test_deduplicator_summary,
        test_deduplicator_with_real_data,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            print(f"✓ {test.__name__} passed")
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1
    
    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)

