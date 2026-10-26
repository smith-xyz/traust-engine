"""The go-callgraph tool as a traust-core tool provider: each main package of a Go checkout
(`go list`) and its call graph (`callgraph -format=digraph`, golang.org/x/tools). Core's
x/crypto enumerator reads the edges; this module only runs the binaries and parses their output.
Loading the packages compiles the module, so it fetches dependencies unless they are vendored."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from traust_core.v1.context import Context
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.code_facts import GO_CALLGRAPH, GoCallgraph, GoEntrypoint
from traust_core.v1.providers.base import Acquisition, Readiness, Result, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolRequest

GO_ENV = ("GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY", "GOFLAGS", "GOPRIVATE", "GONOSUMDB")
TIMEOUT = 300.0  # per main package, as scan_xcrypto_usage.py ran it
_LIST = ["go", "list", "-f", "{{.Name}}\t{{.ImportPath}}\t{{.Dir}}", "./..."]
_EDGE = re.compile(r'^"((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"$')
_TOOLS_MOD = re.compile(r"^\s*mod\s+golang\.org/x/tools\s+(\S+)", re.M)


def _tail(raw: bytes) -> str:
    return raw.decode(errors="replace").strip()[-300:]


def _name(quoted: str) -> str:
    return json.loads(f'"{quoted}"') if "\\" in quoted else quoted


def edges(digraph: str) -> tuple[tuple[str, str], ...]:
    """`callgraph -format=digraph` lines (`"caller" "callee"`, Go-quoted) as edges."""
    found = []
    for line in digraph.splitlines():
        m = _EDGE.match(line)
        if m is None:
            raise ServiceError(f"unparseable callgraph line: {line[:200]!r}")
        found.append((_name(m.group(1)), _name(m.group(2))))
    return tuple(found)


class GoCallgraphTool:
    name = GO_CALLGRAPH

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        return on_path(
            "go", "callgraph", missing=" not on PATH (go install golang.org/x/tools/cmd/callgraph)"
        )

    def acquire(self, request: ToolRequest) -> Result[GoCallgraph]:
        root = request.checkout()
        listed = self._process.run(_LIST, cwd=root, check=False)
        if listed.returncode != 0:
            raise ServiceError(f"go list failed over {root}: {_tail(listed.stderr)}")
        mains = []
        for line in listed.stdout.decode(errors="replace").splitlines():
            name, package, directory = [*line.split("\t", 2), "", ""][:3]
            if name == "main":
                try:
                    rel = Path(directory).resolve().relative_to(root.resolve()).as_posix()
                except ValueError as e:
                    raise ServiceError(f"go list named a package outside {root}: {line}") from e
                mains.append((rel, package))
        graph = GoCallgraph(entrypoints=tuple(self._entry(root, *m) for m in sorted(mains)))
        return Result(
            graph,
            Acquisition(
                provider=self.name,
                acquired_at=self._clock.now(),
                version=self.version(),
                source=str(root),
            ),
        )

    def _entry(self, root: Path, entrypoint: str, package: str) -> GoEntrypoint:
        argv = ["callgraph", "-format=digraph", f"./{entrypoint}"]
        try:
            run = self._process.run(argv, cwd=root, check=False)
            if run.returncode != 0:
                raise ServiceError(_tail(run.stderr) or f"callgraph exited {run.returncode}")
            found = edges(run.stdout.decode(errors="replace"))
        except ServiceError as e:  # one main package failing never hides the others
            return GoEntrypoint(entrypoint=entrypoint, package=package, error=str(e)[:300])
        return GoEntrypoint(entrypoint=entrypoint, package=package, edges=found)

    def version(self) -> str | None:
        binary = shutil.which("callgraph")
        if binary is None:
            return None
        run = self._process.run(["go", "version", "-m", binary], check=False)
        found = _TOOLS_MOD.search(run.stdout.decode(errors="replace"))
        return found.group(1) if found else None

    def database(self) -> DatabaseStatus | None:
        return None

    def update_database(self) -> DatabaseStatus:
        raise NoDatabase(f"{self.name} keeps no database to update")


def register_go_callgraph(ctx: Context) -> None:
    """Register `GoCallgraphTool` in `ctx.tools`, keeping the Go environment it needs."""

    def build() -> GoCallgraphTool:
        keep = (*ctx.config.process.keep_env, *GO_ENV)
        return GoCallgraphTool(
            ProcessRunner(["go", "callgraph"], keep_env=keep, timeout_seconds=TIMEOUT), ctx.clock
        )

    ctx.tools.register(GO_CALLGRAPH, build)
