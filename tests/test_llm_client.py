import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trata.src.config import RuntimeConfig, TargetProjectConfig
from trata.src.storage.models import BuildArtifacts, RunContext
from trata.src.tools.llm_client import LangGraphClient


def test_llm_client_offline_fallback(tmp_path: Path) -> None:
    # Create fake project tree with a single C file
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    file_path = src_dir / "main.c"
    file_path.write_text("void foo() { strcpy(buf, input); }\n", encoding="utf-8")

    build_dir = tmp_path / "build"
    build_dir.mkdir()
    build = BuildArtifacts(
        source_dir=src_dir,
        build_dir=build_dir,
    )
    run_ctx = RunContext(
        project="test",
        run_id="123",
        root=tmp_path,
        logs_dir=tmp_path / "logs",
        artifacts_dir=tmp_path / "artifacts",
    )
    run_ctx.logs_dir.mkdir()
    run_ctx.artifacts_dir.mkdir()

    runtime = RuntimeConfig(workspace_root=tmp_path / "workspace", llm_max_files=1)
    client = LangGraphClient(
        runtime_config=runtime, max_files=runtime.llm_max_files, max_lines=50
    )

    target = TargetProjectConfig(
        name="test",
        repo_url="https://example.com/repo.git",
        fuzz_target="fuzz/fuzzer.c",
    )

    summary, findings = asyncio.run(client.run_static_review(target, build, run_ctx))

    assert len(findings) >= 0
    tool_calls = (run_ctx.logs_dir / "tool_calls.jsonl").read_text(encoding="utf-8")
    assert "source_reader" in tool_calls
    summary_payload = (run_ctx.logs_dir / "llm_summary.json").read_text(encoding="utf-8")
    assert "files" in summary_payload


def test_llm_client_skips_build_artifacts(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    build_dir = tmp_path / "build"
    build_dir.mkdir(parents=True, exist_ok=True)

    (src_dir / "main.c").write_text("int main() { return 0; }", encoding="utf-8")
    objs = src_dir / "objs"
    objs.mkdir()
    (objs / "auto.c").write_text("int unused = 0;", encoding="utf-8")

    build = BuildArtifacts(source_dir=src_dir, build_dir=build_dir)
    run_ctx = RunContext(
        project="test",
        run_id="456",
        root=tmp_path,
        logs_dir=tmp_path / "logs2",
        artifacts_dir=tmp_path / "artifacts2",
    )
    run_ctx.logs_dir.mkdir()
    run_ctx.artifacts_dir.mkdir()

    runtime = RuntimeConfig(workspace_root=tmp_path / "workspace2", llm_max_files=None)
    client = LangGraphClient(runtime_config=runtime, max_files=1, max_lines=20)
    target = TargetProjectConfig(
        name="test",
        repo_url="https://example.com/repo.git",
        fuzz_target="fuzz/fuzzer.c",
    )

    asyncio.run(client.run_static_review(target, build, run_ctx))

    tool_calls = (run_ctx.logs_dir / "tool_calls.jsonl").read_text(encoding="utf-8")
    assert "build_artifact" in tool_calls
    assert "main.c" in tool_calls

