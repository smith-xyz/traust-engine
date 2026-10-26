"""GoCallgraphTool: main packages from `go list`, each one's `callgraph -format=digraph` edges,
a failed package kept as its error. A scripted ProcessRunner answers; the last test runs the real
binaries when they are on PATH."""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.code_facts import GO_CALLGRAPH, GoEntrypoint
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools import NoDatabase, ToolProvider, ToolRequest

from traust_engine.adapters.go_callgraph import GoCallgraphTool, edges, register_go_callgraph

WHEN = datetime(2026, 10, 26, tzinfo=UTC)
DIGRAPH = (
    b'"example.com/app/cmd/app.main" "golang.org/x/crypto/ssh.InsecureIgnoreHostKey"\n'
    b'"(*golang.org/x/crypto/blowfish.Cipher).Encrypt" "golang.org/x/crypto/blowfish.encryptBlock"\n'
)


class Go(ProcessRunner):
    """Answers `go list`, `go version -m` and `callgraph` per package directory."""

    def __init__(self, root: Path, listed: bytes, graphs: dict[str, ProcessResult | bytes]) -> None:
        super().__init__(())
        self.root, self.listed, self.graphs = root, listed, graphs
        self.calls: list[tuple[list[str], Path | None]] = []

    def run(self, argv: Sequence[str], *, cwd: Path | None = None, **_: Any) -> ProcessResult:
        argv = list(argv)
        self.calls.append((argv, cwd))
        if argv[:2] == ["go", "list"]:
            return ProcessResult(tuple(argv), 0, self.listed, b"", 0.0)
        if argv[:2] == ["go", "version"]:
            out = b"/x/callgraph: go1.26\n\tpath\tgolang.org/x/tools/cmd/callgraph\n"
            out += b"\tmod\tgolang.org/x/tools\tv0.38.0\th1:abc=\n"
            return ProcessResult(tuple(argv), 0, out, b"", 0.0)
        answer = self.graphs[argv[-1]]
        if isinstance(answer, ProcessResult):
            return answer
        return ProcessResult(tuple(argv), 0, answer, b"", 0.0)


def listing(root: Path, *rows: tuple[str, str, str]) -> bytes:
    return "".join(f"{n}\t{p}\t{root / d}\n" for n, p, d in rows).encode()


def tool(go: Go) -> GoCallgraphTool:
    return GoCallgraphTool(go, FixedClock(WHEN))


def test_each_main_package_is_graphed_and_a_failed_one_keeps_its_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/x/{b}")
    listed = listing(
        tmp_path,
        ("main", "example.com/app/cmd/app", "cmd/app"),
        ("hash", "example.com/app/pkg/hash", "pkg/hash"),
        ("main", "example.com/app/cmd/broken", "cmd/broken"),
        ("main", "example.com/app", "."),
    )
    broken = ProcessResult((), 1, b"", b"callgraph: packages contain errors\n", 0.0)
    go = Go(tmp_path, listed, {"./cmd/app": DIGRAPH, "./cmd/broken": broken, "./.": b""})
    found = tool(go).acquire(ToolRequest(workspace=tmp_path))
    assert found.data.entrypoints == (
        GoEntrypoint(entrypoint=".", package="example.com/app"),
        GoEntrypoint(
            entrypoint="cmd/app",
            package="example.com/app/cmd/app",
            edges=(
                ("example.com/app/cmd/app.main", "golang.org/x/crypto/ssh.InsecureIgnoreHostKey"),
                (
                    "(*golang.org/x/crypto/blowfish.Cipher).Encrypt",
                    "golang.org/x/crypto/blowfish.encryptBlock",
                ),
            ),
        ),
        GoEntrypoint(
            entrypoint="cmd/broken",
            package="example.com/app/cmd/broken",
            error="callgraph: packages contain errors",
        ),
    )
    assert (found.acquisition.provider, found.acquisition.version) == (GO_CALLGRAPH, "v0.38.0")
    assert all(cwd == tmp_path for argv, cwd in go.calls if argv[0] == "callgraph")


def test_go_list_failing_is_a_service_error(tmp_path: Path) -> None:
    class Broken(Go):
        def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
            return ProcessResult(tuple(argv), 1, b"", b"go: no go.mod\n", 0.0)

    with pytest.raises(ServiceError, match="go list failed"):
        tool(Broken(tmp_path, b"", {})).acquire(ToolRequest(workspace=tmp_path))


def test_a_timed_out_package_keeps_its_error(tmp_path: Path) -> None:
    class Slow(Go):
        def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
            if argv[0] == "callgraph":
                raise ServiceError("callgraph failed to run: timed out after 300 seconds")
            return super().run(argv, **kw)

    go = Slow(tmp_path, listing(tmp_path, ("main", "m", ".")), {})
    (entry,) = tool(go).acquire(ToolRequest(workspace=tmp_path)).data.entrypoints
    assert entry.error is not None and "timed out" in entry.error


def test_edges_parse_go_quoting_and_refuse_anything_else() -> None:
    assert edges('"a.main" "b.\\u00e9t\\"x"\n') == (("a.main", 'b.\u00e9t"x'),)
    assert edges("") == ()
    with pytest.raises(ServiceError, match="unparseable"):
        edges("a.main b.F\n")


def test_registered_with_the_go_environment_and_no_database(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(WHEN))
    register_go_callgraph(ctx)
    found = ctx.tools.get(GO_CALLGRAPH)
    assert isinstance(found, ToolProvider)
    assert found.database() is None
    with pytest.raises(NoDatabase):
        found.update_database()


@pytest.mark.skipif(
    not (shutil.which("go") and shutil.which("callgraph")), reason="go and callgraph not on PATH"
)
def test_the_real_binaries_over_a_stdlib_module(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/m\n\ngo 1.22\n")
    (tmp_path / "cmd" / "m").mkdir(parents=True)
    (tmp_path / "cmd" / "m" / "main.go").write_text(
        'package main\n\nimport "crypto/sha256"\n\nfunc main() { sha256.Sum256(nil) }\n'
    )
    ctx = Context(Config(home=tmp_path / "home"), clock=FixedClock(WHEN))
    register_go_callgraph(ctx)
    (entry,) = ctx.tools.get(GO_CALLGRAPH).acquire(ToolRequest(workspace=tmp_path)).data.entrypoints
    assert (entry.entrypoint, entry.package, entry.error) == ("cmd/m", "example.com/m/cmd/m", None)
    assert ("example.com/m/cmd/m.main", "crypto/sha256.Sum256") in entry.edges
