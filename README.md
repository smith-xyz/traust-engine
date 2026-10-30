# traust-engine

The continuous-ops service for Traust, on traust-core: `traust_engine.ops` runs a
pack's assets through traust-core services. Finding identity, disposition,
persistence, tools and reporting belong to traust-core. Import as `traust_engine`.

## Architecture

| Module | Role |
|---|---|
| `traust_engine.ops` | Continuous ops: `Pack` (the pack's `assets.yaml`, checked against contracts `config/v1/pack`), the tick, admission and the reaper (`EngineLoop.run_once`), all through traust-core services |

This library ships **no configuration files and never loads config itself.**
The service entry point (`traust-engine run|shadow|record|diff|claim --core <core.yaml>
--pack <assets.yaml>`) builds traust-core's `Context` once from the files it is given and
passes core's services in; everything below it takes already-resolved arguments. Config
resolution (`$TRAUST_CONFIG_HOME`, `locations.yaml`) belongs to traust-core's `Context`.
The engine imports only traust-core's public API: `traust_core.v1.context`, `models` and
`errors` (the consumer ratchet in CI holds it there).

Command templates can use `{worker}` alongside `{run_id}`, `{repo_url}`, `{role}` and
`{rule}`. `{worker}` is the claiming runner's ID, so artifact-only session commands can
record their audit evidence under the same lease; claim, heartbeat and completion are unchanged.

## Install

Private Git (after tags are published):

```bash
uv add "traust-engine @ git+ssh://git@<your-forge>/<namespace>/traust-engine.git@v0.1.0"
```

Consumers pin library dependencies by commit, not release tag — a tag
needs a release cut first, a `rev` doesn't, which is what lets the
dependency chain (traust-core to engine) propagate
PR-to-PR instead of waiting on a tag at every hop:

```toml
[project]
dependencies = [
    "traust-engine",
]

[tool.uv.sources]
traust-engine = { git = "git@<your-forge>:<namespace>/traust-engine.git", rev = "<commit-sha>" }
```

Note `dependencies` carries bare names, no `>=` floor — the `rev` above is
the floor now, and a duplicated semver constraint is a second number that
can drift out of sync with it.

Local mono-checkout (sibling repos):

```bash
cd traust-engine && make setup && make test
```

`make setup` runs `uv sync` and enables `.githooks/`. Before opening an MR that
ships user-facing changes, run `make bump patch|minor|major`, add a
`## [X.Y.Z]` section to `CHANGELOG.md`, and `make check-release` (same gate as
CI `release:check-mr`). On merge to `main`, CI tags when `VERSION` is ahead of
the latest tag.

## Runtime configuration

Everything the service needs comes from its arguments: `--core` (traust-core's
`core.yaml`, whose home holds `locations.yaml` and the rest of the deployment config),
`--pack` (the pack's `assets.yaml`), and optionally `--pin`, `--feeds` and `--models`.
Templates for every operational file live in the traust repo as `config/*.example.*`.

## Development

After clone:

```bash
make setup    # uv sync + enable .githooks
make lint
make test
```

Manual equivalents:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build
```

Tests use minimal fixtures under `tests/fixtures/` (an estate-neutral config
home and a pack) — no sibling `traust` checkout required.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
