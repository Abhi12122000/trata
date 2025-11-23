#!/bin/bash

# --- FIX START ---
# 0. Resolve Absolute Path of Target Directory FIRST
# We do this before 'cd'ing so relative paths (like '.') refer to where you ran the script from.
if [ -z "$1" ]; then
    echo "Error: Please provide a source directory."
    exit 1
fi

TARGET_DIR=$(cd "$1" && pwd)
echo "Target Source Directory resolved to: $TARGET_DIR"
# --- FIX END ---

# 1. Setup Directory
DIR_NAME="infer-docker-1.2.0"
if [ ! -d "$DIR_NAME" ]; then
    mkdir -p "$DIR_NAME"
fi
cd "$DIR_NAME"

# 2. Fetch Dockerfile
if [ -f "Dockerfile" ]; then
    echo "Dockerfile already exists"
else
    echo "Downloading Dockerfile..."
    curl -o Dockerfile https://raw.githubusercontent.com/facebook/infer/main/docker/1.2.0/Dockerfile
fi

# 3. Build Image
if [[ "$(docker images -q infer-1.2.0 2> /dev/null)" == "" ]]; then
    echo "Building Docker image..."
    docker build -t infer-1.2.0 .
fi

# 4. Run Analysis
echo "Running Infer analysis on $TARGET_DIR..."

# Note: We are redirecting logs to the current directory (which is inside infer-docker-1.2.0)
docker run --rm -v "$TARGET_DIR":/app -w /app infer-1.2.0 \
/bin/sh -c "infer run -- clang -c \$(find . -name '*.c') > stdout.log 2> stderr.log"

echo "Analysis complete."
echo "Logs: $DIR_NAME/stdout.log and $DIR_NAME/stderr.log"
echo "Results: $TARGET_DIR/infer-out"