#!/bin/bash
# Build script for example-c-target
#
# This script builds:
# 1. Static library (libvuln.a) for static analysis
# 2. Standalone binary (vuln) for manual testing
# 3. compile_commands.json for Infer
# 4. Fuzzer binaries (if clang with libFuzzer is available)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "[build] Starting build in $ROOT_DIR"

# Create build directory
mkdir -p build
rm -rf build/*

# ============================================================================
# Step 1: Build static library and standalone binary (for static analysis)
# ============================================================================
echo "[build] Compiling vuln.c -> build/vuln.o"
cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector \
    -I src \
    -c src/vuln.c -o build/vuln.o

echo "[build] Creating static library build/libvuln.a"
ar rcs build/libvuln.a build/vuln.o

echo "[build] Building standalone binary build/vuln"
cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector \
    -I src \
    src/vuln.c src/main.c -o build/vuln

# ============================================================================
# Step 2: Generate compile_commands.json for Infer
# ============================================================================
echo "[build] Generating compile_commands.json"
cat > build/compile_commands.json << EOF
[
  {
    "directory": "$ROOT_DIR",
    "command": "cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector -I src -c src/vuln.c -o build/vuln.o",
    "file": "$ROOT_DIR/src/vuln.c"
  },
  {
    "directory": "$ROOT_DIR",
    "command": "cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector -I src -c src/main.c -o build/main.o",
    "file": "$ROOT_DIR/src/main.c"
  }
]
EOF

# ============================================================================
# Step 3: Build fuzzer binaries (optional - requires clang with libFuzzer)
# ============================================================================
echo "[build] Checking for clang with libFuzzer support..."

# Find clang (prefer Homebrew LLVM)
CLANG=""
if [ -x "/opt/homebrew/opt/llvm/bin/clang" ]; then
    CLANG="/opt/homebrew/opt/llvm/bin/clang"
elif [ -x "/usr/local/opt/llvm/bin/clang" ]; then
    CLANG="/usr/local/opt/llvm/bin/clang"
elif command -v clang &> /dev/null; then
    CLANG="$(command -v clang)"
fi

FUZZER_BUILD_SUCCESS=false

if [ -n "$CLANG" ]; then
    # Test if clang supports -fsanitize=fuzzer
    if $CLANG -fsanitize=fuzzer -x c -c /dev/null -o /dev/null 2>/dev/null; then
        echo "[build] Found clang with libFuzzer: $CLANG"
        
        # Determine extra flags for Homebrew LLVM
        EXTRA_FLAGS=""
        if [[ "$CLANG" == *"/opt/homebrew/opt/llvm"* ]]; then
            EXTRA_FLAGS="-L/opt/homebrew/opt/llvm/lib/c++ -Wl,-rpath,/opt/homebrew/opt/llvm/lib/c++"
        elif [[ "$CLANG" == *"/usr/local/opt/llvm"* ]]; then
            EXTRA_FLAGS="-L/usr/local/opt/llvm/lib/c++ -Wl,-rpath,/usr/local/opt/llvm/lib/c++"
        fi
        
        # Build main fuzzer (vuln_fuzzer)
        echo "[build] Building fuzzer: build/vuln_fuzzer"
        if $CLANG -fsanitize=fuzzer,address -g -O1 -fno-omit-frame-pointer \
            -I src \
            $EXTRA_FLAGS \
            src/vuln.c fuzz/vuln_fuzzer.c \
            -o build/vuln_fuzzer 2>&1; then
            echo "[build] Successfully built build/vuln_fuzzer"
            FUZZER_BUILD_SUCCESS=true
        else
            echo "[build] WARNING: Failed to build vuln_fuzzer"
        fi
        
        # Build packet fuzzer
        echo "[build] Building fuzzer: build/packet_fuzzer"
        if $CLANG -fsanitize=fuzzer,address -g -O1 -fno-omit-frame-pointer \
            -I src \
            $EXTRA_FLAGS \
            src/vuln.c fuzz/packet_fuzzer.c \
            -o build/packet_fuzzer 2>&1; then
            echo "[build] Successfully built build/packet_fuzzer"
        else
            echo "[build] WARNING: Failed to build packet_fuzzer"
        fi
    else
        echo "[build] WARNING: clang found but doesn't support -fsanitize=fuzzer"
    fi
else
    echo "[build] WARNING: clang not found"
fi

if [ "$FUZZER_BUILD_SUCCESS" = false ]; then
    echo "[build] NOTE: Fuzzer binaries not built. Static analysis will still work."
    echo "[build] To enable fuzzing on macOS, install: brew install llvm"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "[build] Build complete!"
echo "[build] Artifacts:"
ls -la build/
