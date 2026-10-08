"""Artifact-first PostgreSQL rehearsal with two reports and a retained database."""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import sqlite3
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Literal

from traust_contracts.paths import schema_dir, storage_dir
from traust_contracts.v1.storage import Binding, IngestError
from traust_contracts.v1.storage import store as contracts_store

from traust_engine.corpus import (
    migration_database,
    migration_discovery,
    migration_projection,
    migration_validation,
    migration_workers,
    store_ingest,
)
from traust_engine.corpus.migration_database import (
    ImportStrategy,
    MigrationTarget,
    acquire_run_lock,
    save_decisions,
    save_result,
)
from traust_engine.corpus.migration_discovery import (
    Artifact,
    ArtifactCatalog,
    DiscoveryError,
    MigrationOptions,
    load_config,
)
from traust_engine.corpus.migration_validation import (
    NumberRepresentationError,
    parse_document,
)


@dataclass(slots=True)
class SourceDecision:
    source_file: str
    reason: str | None = None
    source_digest: str | None = None
    digest_status: str | None = None
    artifact: str | None = None
    namespace: str | None = None
    layer_id: str | None = None
    product_repo_id: str | None = None
    context_selection: dict[str, str] | None = None

    def receipt(self, state: str) -> dict[str, Any]:
        fields = asdict(self)
        return {
            **{key: value for key, value in fields.items() if value is not None or key == "reason"},
            "decision": state,
        }


@dataclass(frozen=True, slots=True)
class ImportPlan:
    binding: Binding
    repository: tuple[str, str, str] | None


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _fingerprint(values: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def _contract_pins() -> dict[str, str]:
    files = {
        *schema_dir().glob("*.json"),
        *storage_dir().rglob("*.sql"),
        storage_dir() / "profiles.json",
        Path(__file__),
        *(
            Path(inspect.getfile(module))
            for module in (
                contracts_store,
                migration_database,
                migration_discovery,
                migration_projection,
                migration_validation,
                migration_workers,
                store_ingest,
            )
        ),
    }
    return {str(path): digest(path) for path in sorted(files)}


def _check_pins(pins: dict[str, str]) -> None:
    if any(digest(Path(path)) != expected for path, expected in pins.items()):
        raise RuntimeError("Source, configuration, or implementation changed during rehearsal")


def _sqlite_inventory(path: Path) -> dict[str, Any]:
    before = digest(path)
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-journal")):
        raise ValueError("SQLite must be a closed, checkpointed snapshot")
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        counts = {}
        for (name,) in conn.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall():
            quoted = '"' + name.replace('"', '""') + '"'
            counts[name] = conn.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0]
    finally:
        conn.close()
    if digest(path) != before:
        raise RuntimeError("SQLite snapshot changed while reading")
    return {
        "status": "reference_only",
        "parity_checked": False,
        "path": str(path),
        "sha256": before,
        "table_counts": counts,
    }


class Rehearsal:
    def __init__(
        self,
        root: Path,
        config: Path,
        output: Path,
        max_seconds: float | None,
        route_layers_to_ledger: bool = False,
        exclude: list[str] | None = None,
    ) -> None:
        self.root, self.config_path, self.output = root, config, output
        self.route_layers_to_ledger = route_layers_to_ledger
        self.decisions: dict[str, SourceDecision] = {}
        self.layer_ids: dict[str, str] = {}
        self.deadline = time.monotonic() + max_seconds if max_seconds is not None else None
        self.started_at = time.perf_counter()
        self.active_phase: tuple[str, float] | None = None
        self.phase_seconds: dict[str, float] = {}
        corpus, options = load_config(config)
        if exclude:
            # Profile/CLI excludes add to the deployment config's migration.exclude.
            options = MigrationOptions.model_validate(
                {**options.model_dump(), "exclude": [*options.exclude, *exclude]}
            )
        self.catalog = ArtifactCatalog(root, corpus, options)
        self.sources: dict[str, str] = {}
        self.states: dict[str, str] = {}
        self.errors: Counter[str] = Counter()
        self.exclusions: Counter[str] = Counter()
        self.reserved: Counter[str] = Counter()
        self.plans: dict[str, ImportPlan] = {}
        self.blocking_issues = 0
        self.pins = _contract_pins() | {str(config): digest(config)}
        self.result: dict[str, Any] = {
            "status": "blocked",
            "source_root": str(root),
            "config": str(config),
            "run_state": "running",
            "diagnostics_complete": False,
            "migration_ready": False,
            "database_retained": None,
            "reconciliation": {"passed": False, "source_unchanged": False},
            "views": "deferred",
            "comparison": {"status": "not_requested"},
        }

    def check_budget(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError("Rehearsal time budget exhausted")

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        self.active_phase = (name, started)
        try:
            yield
        finally:
            self.phase_seconds[name] = round(time.perf_counter() - started, 3)
            self.active_phase = None
            self.checkpoint()

    def checkpoint(self) -> None:
        now = time.perf_counter()
        ledger = self.result.get("ledger")
        if not ledger or ledger["status"] == "not_run":
            ledger = {
                "status": "not_run",
                "selected": sum(
                    item.namespace == "traust_ledger"
                    and self.states.get(relative) in {"selected", "delegated"}
                    for relative, item in self.decisions.items()
                ),
            }
        self.result.update(
            issue_count=sum(self.errors.values()),
            issue_counts=dict(self.errors),
            blocking_issue_count=self.blocking_issues,
            outcomes=dict(Counter(self.states.values())),
            excluded_by_rule=dict(self.exclusions),
            reserved_directories=dict(self.reserved),
            ledger=ledger,
            timing={
                "elapsed_seconds": round(now - self.started_at, 3),
                "phase_seconds": dict(self.phase_seconds),
                "active_phase": self.active_phase[0] if self.active_phase else None,
                "active_seconds": round(now - self.active_phase[1], 3)
                if self.active_phase
                else None,
            },
        )
        save_result(self.output, self.result)

    def receipts(self) -> list[dict[str, Any]]:
        return [
            self.decisions[relative].receipt(self.states[relative])
            for relative in sorted(self.states)
        ]

    def issue(self, code: str, *, blocking: bool = True, **detail: Any) -> None:
        self.errors[code] += 1
        self.blocking_issues += int(blocking)
        source_file = detail.get("source_file")
        if isinstance(source_file, str) and source_file in self.decisions:
            self.decisions[source_file].reason = code
        entry = {
            **detail,
            "id": f"ISSUE-{sum(self.errors.values()):06d}",
            "status": "open",
            "error_class": code,
            "blocking": blocking,
            "decision": None,
        }
        with (self.output / "issues.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=True) + "\n")
        if sum(self.errors.values()) % 100 == 0:
            self.checkpoint()

    def paths(self, *, record_reserved: bool = False) -> Iterator[Path]:
        def failed(error: OSError) -> None:
            raise error

        for directory, names, files in os.walk(self.root, followlinks=False, onerror=failed):
            parent = Path(directory)
            for name in sorted(names):
                if name == ".git":
                    if record_reserved:
                        self.reserved[name] += 1
                elif (parent / name).is_symlink():
                    yield parent / name
            names[:] = sorted(n for n in names if n != ".git" and not (parent / n).is_symlink())
            for name in sorted(files):
                if name.endswith(".json"):
                    yield parent / name

    def inventory(self) -> None:
        for index, path in enumerate(self.paths(record_reserved=True)):
            self.check_budget()
            relative = path.relative_to(self.root).as_posix()
            candidate = self.catalog.is_candidate(relative)
            exclusion = (
                "navigation_alias"
                if path.is_symlink()
                else self.catalog.options.exclusion(relative)
            )
            self.decisions[relative] = SourceDecision(relative, exclusion)
            if not candidate and not exclusion:
                self.decisions[relative].reason = "no_filename_route"
                self.states[relative] = "unselected"
                continue
            if exclusion:
                if (
                    not path.is_symlink()
                    and path.is_file()
                    and path.resolve().is_relative_to(self.root)
                ):
                    try:
                        self.decisions[relative].source_digest = digest(path)
                    except OSError:
                        self.decisions[relative].digest_status = "unavailable"
                self.exclusions[exclusion] += 1
                self.states[relative] = "excluded"
                continue
            self.states[relative] = "pending"
            if not path.resolve().is_relative_to(self.root):
                self.issue("unsafe_source_path", source_file=relative)
                self.states[relative] = "rejected"
                continue
            if path.is_dir():
                self.issue(
                    "directory_symlink",
                    source_file=relative,
                    factual_message=(
                        "Directory aliases are not traversed; "
                        "provide the target root or exclude explicitly"
                    ),
                )
                self.states[relative] = "rejected"
                continue
            try:
                payload = path.read_bytes()
                self.sources[str(path)] = hashlib.sha256(payload).hexdigest()
                self.decisions[relative].source_digest = self.sources[str(path)]
                document = parse_document(payload)
                artifact = self.catalog.identify(relative, document)
                self.catalog.add(artifact, document)
                self.decisions[relative].artifact = artifact.family
                self.decisions[relative].namespace = (
                    "traust_ledger"
                    if artifact.family == "layer" and self.route_layers_to_ledger
                    else "traust_storage"
                )
            except DiscoveryError as error:
                self.issue(error.code, source_file=relative, factual_message=str(error))
                self.states[relative] = "unrecognized"
            except NumberRepresentationError as error:
                self.issue(
                    "number_representation", source_file=relative, factual_message=str(error)
                )
                self.states[relative] = "rejected"
            except (ValueError, UnicodeError, OSError) as error:
                self.issue(
                    "unreadable_source" if isinstance(error, OSError) else "invalid_json",
                    source_file=relative,
                    exception_type=type(error).__name__,
                )
                self.states[relative] = "rejected"
            if index % 100 == 0:
                self.checkpoint()
        self.result["inventory"] = {
            "candidate_paths": len(self.states),
            "recognized_artifacts": len(self.catalog.artifacts),
            "source_inventory_sha256": _fingerprint(self.sources),
            "contract_and_config_sha256": _fingerprint(self.pins),
        }
        if not self.catalog.artifacts:
            self.issue(
                "no_selected_inputs",
                factual_message="No candidate JSON selected under the input root",
            )
        _check_pins(self.pins)

    def claim_layer(self, relative: str, layer_id: str | None) -> None:
        if not layer_id or (layer_id in self.layer_ids and self.layer_ids[layer_id] != relative):
            raise DiscoveryError("ambiguous_binding", "Ledger layer ID is absent or duplicated")
        self.layer_ids[layer_id] = relative
        self.decisions[relative].layer_id = layer_id

    def source_bytes(self, relative: str) -> bytes:
        path = self.root / relative
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != self.sources[str(path)]:
            raise RuntimeError("Source changed after inventory")
        return payload

    def pending(self) -> Iterator[Artifact]:
        return (a for a in self.catalog.artifacts.values() if self.states[a.relative] == "pending")

    def load(self, database: ImportStrategy) -> None:
        with self.phase("validate"):
            self.validate_sources()
            self.resolve_sources()
        with self.phase("registry"):
            self.register_repositories(database)
        _check_pins(self.pins)
        with self.phase("ingest"):
            self.ingest_artifacts(database)

    def validate_sources(self) -> None:
        self.catalog.reset_index()
        workers = self.catalog.options.validation_workers
        self.result["validation_workers"] = workers
        tasks = (
            (str(self.root / a.relative), a.family, self.sources[str(self.root / a.relative)])
            for a in self.pending()
        )
        processed = 0
        for (name, _, _), failures in migration_workers.validation_results(tasks, workers):
            self.check_budget()
            relative = Path(name).relative_to(self.root).as_posix()
            if failures:
                for detail in failures:
                    code = detail.pop("error_class")
                    self.issue(code, **(detail | {"source_file": relative}))
                self.states[relative] = "rejected"
                continue
            self.catalog.add(
                self.catalog.artifacts[relative], parse_document(self.source_bytes(relative))
            )
            processed += 1
            if processed % 500 == 0:
                self.result["validation_processed"] = processed
                self.checkpoint()
        self.result["validation_processed"] = processed

    def resolve_sources(self) -> None:
        """Bind every valid artifact to its context and product/repo without touching a database."""
        for artifact in self.pending():
            relative = artifact.relative
            decision = self.decisions[relative]
            try:
                document = parse_document(self.source_bytes(relative))
                binding = self.catalog.binding(artifact, document)
                repository = self.catalog.repository(artifact, document, binding)
                decision.context_selection = self.catalog.context_selections.get(relative)
                if repository is None and decision.namespace == "traust_ledger":
                    raise DiscoveryError(
                        "unresolved_repository", "Ledger layer needs a product_repo"
                    )
                metadata = document.get("metadata")
                commit = metadata.get("commit") if isinstance(metadata, dict) else None
                if commit is not None and (not isinstance(commit, str) or not commit):
                    raise DiscoveryError("ambiguous_repository", "Invalid artifact commit")
                if decision.namespace == "traust_ledger":
                    self.claim_layer(relative, binding.layer_id)
                self.plans[relative] = ImportPlan(replace(binding, commit_sha=commit), repository)
            except DiscoveryError as error:
                self.issue(error.code, source_file=relative, factual_message=str(error))
                self.states[relative] = "blocked"

    def register_repositories(self, database: ImportStrategy) -> None:
        registered: dict[tuple[str, str, str], str] = {}
        for artifact in self.pending():
            plan = self.plans[artifact.relative]
            if plan.repository is None:
                continue
            if plan.repository not in registered:
                self.check_budget()
                registered[plan.repository] = database.register_repository(*plan.repository)
            product_repo_id = registered[plan.repository]
            self.result["registered_contexts"] = len(registered)
            self.decisions[artifact.relative].product_repo_id = product_repo_id
            self.plans[artifact.relative] = replace(
                plan, binding=replace(plan.binding, product_repo_id=product_repo_id)
            )

    def ingest_artifacts(self, database: ImportStrategy) -> None:
        for index, artifact in enumerate(self.pending()):
            self.check_budget()
            if index % 500 == 0:
                self.checkpoint()
            relative = artifact.relative
            if self.decisions[relative].namespace == "traust_ledger":
                self.states[relative] = "delegated"
                continue
            try:
                saved = database.ingest(
                    artifact.family, self.source_bytes(relative), self.plans[relative].binding
                )
            except IngestError as error:
                database.check_healthy()
                self.issue(
                    "ingest_rejected",
                    source_file=relative,
                    artifact=artifact.family,
                    factual_message=str(error),
                )
                self.states[relative] = "rejected"
                continue
            except (KeyError, TypeError, ValueError) as error:
                database.check_healthy()
                self.issue(
                    "mapping_failure",
                    source_file=relative,
                    artifact=artifact.family,
                    exception_type=type(error).__name__,
                )
                self.states[relative] = "blocked"
                continue
            self.states[relative] = "already_bound" if saved.already_bound else "ingested"

    def reconcile(self, database: ImportStrategy) -> None:
        if set(self.states) != {p.relative_to(self.root).as_posix() for p in self.paths()}:
            raise RuntimeError("Source inventory changed during rehearsal")
        _check_pins(self.sources)
        _check_pins(self.pins)
        expected, actual = database.reconcile()
        passed = self.blocking_issues == 0 and all(
            state in {"ingested", "already_bound", "excluded", "unselected", "delegated"}
            for state in self.states.values()
        )
        self.result["reconciliation"] = {
            "passed": passed,
            "source_unchanged": True,
            "loaded_artifacts_verified": True,
            "checks": list(database.checks),
            "expected_rows": expected,
            "actual_rows": actual,
        }
        self.result.update(diagnostics_complete=True, status="passed" if passed else "failed")


def preview(
    results: Path,
    config: Path,
    output: Path,
    *,
    route_layers_to_ledger: bool = False,
    exclude: list[str] | None = None,
) -> dict[str, Any]:
    """Validate selected sources without opening or creating a database."""
    results, config, output = results.resolve(), config.resolve(), output.resolve()
    if not results.is_dir() or not config.is_file():
        raise ValueError("Results directory and deployment config must exist")
    if output == results or results in output.parents:
        raise ValueError("Output must be outside the read-only source tree")
    run = Rehearsal(results, config, output, None, route_layers_to_ledger, exclude)
    output.mkdir(parents=True, exist_ok=False)
    with acquire_run_lock(output):
        (output / "issues.jsonl").touch(exist_ok=False)
        try:
            run.inventory()
            run.validate_sources()
            run.resolve_sources()
            for artifact in run.pending():
                run.states[artifact.relative] = "selected"
            if set(run.states) != {p.relative_to(results).as_posix() for p in run.paths()}:
                raise RuntimeError("Source inventory changed during preview")
            _check_pins(run.sources)
            _check_pins(run.pins)
            run.result.update(status="planned", diagnostics_complete=True)
        except (Exception, KeyboardInterrupt) as error:
            run.issue("systemic_failure", exception_type=type(error).__name__)
            run.result.update(status="blocked", diagnostics_complete=False)
        finally:
            run.result.update(run_state="finished", database_retained=False)
            save_decisions(output, run.receipts())
            run.checkpoint()
    return run.result


def rehearse(
    results: Path,
    config: Path,
    dsn: str,
    output: Path,
    *,
    findings_db: Path | None = None,
    max_seconds: float | None = None,
    database_factory: Callable[[str], ImportStrategy] = MigrationTarget.postgres,
    route_layers_to_ledger: bool = False,
    database_type: Literal["postgres", "sqlite"] = "postgres",
    exclude: list[str] | None = None,
    ledger_target_url: str | None = None,
) -> dict[str, Any]:
    results, config, output = results.resolve(), config.resolve(), output.resolve()
    if not results.is_dir() or not config.is_file():
        raise ValueError("Results directory and deployment config must exist")
    if output == results or results in output.parents:
        raise ValueError("Output must be outside the read-only source tree")
    if max_seconds is not None and (not math.isfinite(max_seconds) or max_seconds <= 0):
        raise ValueError("max_seconds must be finite and positive")
    if database_type not in {"postgres", "sqlite"}:
        raise ValueError("Unsupported database type")
    if ledger_target_url and not route_layers_to_ledger:
        raise ValueError("Ledger target requires layer destination ledger")
    if database_type == "sqlite":
        target = Path(dsn).resolve()
        if any(target == parent or parent in target.parents for parent in (results, output)):
            raise ValueError("SQLite target must be outside source and output trees")
    run = Rehearsal(results, config, output, max_seconds, route_layers_to_ledger, exclude)
    output.mkdir(parents=True, exist_ok=False)
    with acquire_run_lock(output):
        (output / "issues.jsonl").touch(exist_ok=False)
        database = None
        run.checkpoint()
        try:
            with run.phase("inventory"):
                run.inventory()
            run.check_budget()
            database = (
                MigrationTarget.sqlite(Path(dsn))
                if database_type == "sqlite"
                else database_factory(dsn)
            )
            run.result.update(database=database.name, database_retained=True)
            run.checkpoint()
            with run.phase("bootstrap"):
                database.initialize()
            if database_type == "sqlite":
                run.result["views"] = "installed; dashboard compatibility not verified"
            run.load(database)
            with run.phase("reconcile"):
                run.reconcile(database)
            run.checkpoint()
            run.check_budget()
            if ledger_target_url and run.result["reconciliation"]["passed"]:
                from traust_ledger._internal.historical_migration import (
                    iter_manifest_layers,
                    migrate,
                )

                save_decisions(output, run.receipts())
                selected = run.result["ledger"]["selected"]
                if selected:
                    counts: Counter[str] = Counter()
                    for item in migrate(
                        iter_manifest_layers(results, output / "decisions.jsonl"),
                        ledger_target_url,
                    ):
                        counts[item.status] += 1
                        if item.status not in {"inserted", "skipped"}:
                            run.issue(
                                "ledger_migration_rejected",
                                source_file=item.source,
                                layer_id=item.layer_id,
                                factual_message=item.detail or item.status,
                            )
                    run.result["ledger"] = {
                        "status": "passed" if not run.blocking_issues else "failed",
                        "selected": selected,
                        "counts": dict(counts),
                    }
                    if sum(counts.values()) != selected or run.blocking_issues:
                        run.result["status"] = "failed"
                run.check_budget()
            if findings_db is not None:
                try:
                    run.result["comparison"] = _sqlite_inventory(findings_db.resolve())
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    run.result["comparison"] = {"status": "unavailable", "parity_checked": False}
                    run.issue(
                        "comparison_unavailable",
                        blocking=False,
                        exception_type=type(error).__name__,
                    )
            run.check_budget()
        except (Exception, KeyboardInterrupt) as error:
            run.issue(
                "systemic_failure",
                exception_type=type(error).__name__,
                sqlstate=getattr(error, "sqlstate", None),
                detail=str(error)[:500],
                factual_message="Run stopped; database retained, no source changes authorized",
            )
            run.result.update(status="blocked", diagnostics_complete=False)
        finally:
            if database is not None:
                try:
                    database.close()
                except Exception as error:
                    run.issue("connection_close_failed", exception_type=type(error).__name__)
                    run.result.update(status="blocked", diagnostics_complete=False)
            run.result["migration_ready"] = bool(
                run.result["status"] == "passed"
                and run.result["diagnostics_complete"]
                and run.blocking_issues == 0
                and run.result["reconciliation"]["passed"]
                and (
                    "delegated" not in run.states.values()
                    or run.result["ledger"]["status"] == "passed"
                )
            )
            run.result["run_state"] = "finished"
            save_decisions(output, run.receipts())
            run.checkpoint()
        return run.result
