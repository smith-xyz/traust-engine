# traust-engine

The continuous-ops service for Traust, on traust-core: `traust_engine.ops` runs a
pack's assets through traust-core services. Finding identity, disposition,
persistence, tools and reporting belong to traust-core. Import as `traust_engine`.

## Architecture

| Module | Role |
|---|---|
| `traust_engine.ops` | Continuous ops: `Pack` (the pack's `assets.yaml`, checked against contracts `config/v1/pack`), the tick, admission and the reaper (`EngineLoop.run_once`), all through traust-core services |

Kept for traust until Shaun's retire-or-port decisions land (each package is
tagged `PENDING(decision: …)`); deleted when traust retires or ports it:

| Module | Kept for |
|---|---|
| `traust_engine.engine` | `HarnessEngine` facade: `.metrics`, `.models`, `.adapters`, `.sweep`, `.portfolio` |
| `traust_engine.sweep` | sweep stages: collect, draft, sweep, emit, benchmark, rule lane, mining, calibration |
| `traust_engine.portfolio` | portfolio graph layers |
| `traust_engine.metrics`, `traust_engine.registry` | metrics journal and spend pricing |
| `traust_engine.adapters` | opengrep (sweep stages) and checkov (portfolio graph) |
| `traust_engine.corpus` | the report population the sweep stages read |

The opengrep rule pack ships under `data/secure-code-audit/opengrep-rules/`. This library ships **no configuration files and never loads
config itself — it is a pure consumer.** A caller builds the context once
(`traust_contracts.load_context()`, done for you by
`HarnessEngine.load(config_home=…)`) and the engine receives it *injected*: the
ops namespaces (`h.metrics`, `h.adapters`, …) hold the frozen `HarnessContext` and
derive paths from it; stateless functions take already-resolved arguments. No
environment overrides, no cwd or workspace-shaped guessing; a required-but-absent
file fails closed with `DeploymentConfigMissing` at the entry point. The config
ownership model (contract / resolution / consumer) is documented in
`traust/docs/architecture.md` → *Configuration & context*; the runtime paths this
engine reads from `locations.yaml` are in *Runtime configuration* below.

## Install

Private Git (after tags are published):

```bash
uv add "traust-engine @ git+ssh://git@<your-forge>/<namespace>/traust-engine.git@v0.1.0"
```

Consumers pin library dependencies by commit, not release tag — a tag
needs a release cut first, a `rev` doesn't, which is what lets the
dependency chain (contracts to ledger to engine to downstream) propagate
PR-to-PR instead of waiting on a tag at every hop:

```toml
[project]
dependencies = [
    "traust-engine",
    "traust-ledger",
    "traust-contracts",
]

[tool.uv.sources]
traust-engine = { git = "git@<your-forge>:<namespace>/traust-engine.git", rev = "<commit-sha>" }
traust-ledger = { git = "git@<your-forge>:<namespace>/traust-ledger.git", rev = "<commit-sha>" }
traust-contracts = { git = "git@<your-forge>:<namespace>/traust-contracts.git", rev = "<commit-sha>" }
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

## Optional extras

```bash
uv sync --extra graph --extra signing
```

## Runtime configuration

Runtime configuration is **config-owned** — there are no environment overrides for
deployment values. One directory, `$TRAUST_CONFIG_HOME` (default `~/.traust/config`),
holds every config file; edit them there (the AWS/SSH model).

| Config | Purpose |
|---|---|
| `$TRAUST_CONFIG_HOME` | The one config directory (corpus-config, model-registry, feeds, external-tools, safe-exec profiles, product map, budget policy, rule-pack allowlist, hardening weights, dist-git watch, internal vocabulary, optional signing pubkey). Default `~/.traust/config`; else `DeploymentConfigMissing`. |
| `locations.yaml` → `workspace` | Workspace root the harness reads repos from |
| `locations.yaml` → `analysis_results` | Findings-side artifact root (local path or `file://`/`s3://`… URI) |
| `locations.yaml` → `progress_tracker` | Metrics journal + dashboard output root |
| `locations.yaml` → `feeds_cache` | Feed cache directory |
| `locations.yaml` → `portfolio_graph` | Portfolio graph DB (defaults under `analysis_results`) |
| `locations.yaml` → `opengrep_rules` | Opengrep rule pack dir (overrides the bundled default) |

Secrets and OS/tool standards stay environment-driven (`GITHUB_TOKEN`, signing key
material, `XDG_*`, `JAVA_OPTS`).

No config ships in the wheel. Templates for every operational file live in the
harness repo as `config/*.example.*`; `install_traust` copies them into
`$TRAUST_CONFIG_HOME`.

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
uv run pytest -m "not integration" -q   # unit tests (no external binaries)
uv run pytest -q                        # full suite; integration skips when opengrep is absent
uv build
```

Tests use minimal scanner fixtures under `tests/fixtures/` — no sibling
`traust` checkout required.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
