#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

mkdir -p build
rm -rf build/*

# ============================================================================
# Standard build (for Infer static analysis)
# ============================================================================
cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector -c src/vuln.c -o build/vuln.o
cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector src/vuln.c -o build/vuln
ar rcs build/libvuln.a build/vuln.o

# Generate compile_commands.json for Infer
cat > build/compile_commands.json <<'EOF'
[
  {
    "directory": "%s",
    "command": "cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector -c src/vuln.c -o build/vuln.o",
    "file": "src/vuln.c"
  }
]
EOF
python3 - <<PY
from pathlib import Path
root = Path(r"$ROOT_DIR")
cc = root / "build/compile_commands.json"
data = cc.read_text()
cc.write_text(data % root)
PY

echo "[example-c-target] standard build complete: build/libvuln.a"

# ============================================================================
# Fuzzer build (for libFuzzer)
# Requires clang with fuzzer support
# ============================================================================
FUZZER_BUILD="${FUZZER_BUILD:-1}"

if [ "$FUZZER_BUILD" = "1" ]; then
    # Try to find clang with libFuzzer support
    # Priority: Homebrew LLVM > System clang
    CLANG=""
    
    # Check Homebrew LLVM first (macOS)
    if [ -x "/opt/homebrew/opt/llvm/bin/clang" ]; then
        CLANG="/opt/homebrew/opt/llvm/bin/clang"
    elif [ -x "/usr/local/opt/llvm/bin/clang" ]; then
        CLANG="/usr/local/opt/llvm/bin/clang"
    elif command -v clang &> /dev/null; then
        CLANG="clang"
    fi

    if [ -z "$CLANG" ]; then
        echo "[example-c-target] WARNING: clang not found, skipping fuzzer build"
        echo "[example-c-target] To enable fuzzing, install LLVM: brew install llvm"
        exit 0
    fi

    # Check if clang supports -fsanitize=fuzzer (compile only, no link)
    if ! $CLANG -fsanitize=fuzzer -x c -c /dev/null -o /dev/null 2>/dev/null; then
        echo "[example-c-target] WARNING: $CLANG doesn't support -fsanitize=fuzzer"
        echo "[example-c-target] To enable fuzzing on macOS: brew install llvm"
        echo "[example-c-target] Then: export PATH=\"/opt/homebrew/opt/llvm/bin:\$PATH\""
        exit 0
    fi

    echo "[example-c-target] building fuzzer binary with $CLANG..."

    # Build with AddressSanitizer + libFuzzer
    # -fsanitize=fuzzer: links libFuzzer and instruments for coverage
    # -fsanitize=address: detects memory errors (UAF, buffer overflow, etc.)
    # -g: debug symbols for better crash reports
    # -O1: some optimization (libFuzzer works better with -O1 or -O2)
    if $CLANG -fsanitize=fuzzer,address -g -O1 \
        src/vuln.c fuzz/vuln_fuzzer.c \
        -o build/vuln_fuzzer 2>&1; then
        echo "[example-c-target] fuzzer build complete: build/vuln_fuzzer"
    else
        echo "[example-c-target] WARNING: fuzzer build failed"
        echo "[example-c-target] Static analysis will still work, but fuzzing is disabled"
        exit 0
    fi
fi
