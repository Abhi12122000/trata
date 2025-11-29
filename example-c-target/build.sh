#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

mkdir -p build
rm -rf build/*
cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector -c src/vuln.c -o build/vuln.o
cc -g -O0 -std=c11 -Wall -Wextra -fno-stack-protector src/vuln.c -o build/vuln
ar rcs build/libvuln.a build/vuln.o

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

echo "[example-c-target] build complete: build/libvuln.a"

