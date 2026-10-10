"""Load an operator-selected empty database; never create, stamp, reset, or drop it."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal, Protocol

from traust_contracts.v1.storage import Binding, IngestResult

from traust_engine.corpus.migration_projection import Expectations, RecordingStore

BUNDLE = ("migration-result.json", "issues.jsonl", "decisions.jsonl")
CHECKS = ("evidence_pointer", "binding_context", "projection_values_and_multiplicity", "row_counts")


class TargetNotEmpty(ValueError):
    pass


class TargetInUse(ValueError):
    pass


class ImportStrategy(Protocol):
    name: str
    checks: tuple[str, ...]

    def initialize(self) -> None: ...
    def register_repository(self, slug: str, url: str, ref: str) -> str: ...
    def ingest(self, artifact: str, payload: bytes, binding: Binding) -> IngestResult: ...
    def check_healthy(self) -> None: ...
    def reconcile(self) -> tuple[dict[str, int], dict[str, int]]: ...
    def close(self) -> None: ...


def save_result(output: Path, result: dict[str, Any]) -> None:
    temporary = output / "migration-result.json.tmp"
    temporary.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    temporary.replace(output / "migration-result.json")


def save_decisions(output: Path, decisions: list[dict[str, Any]]) -> None:
    temporary = output / "decisions.jsonl.tmp"
    with temporary.open("w", encoding="utf-8") as stream:
        for decision in decisions:
            stream.write(json.dumps({"format_version": 1, **decision}, ensure_ascii=True) + "\n")
    temporary.replace(output / "decisions.jsonl")


@contextmanager
def acquire_run_lock(output: Path) -> Generator[None, None, None]:
    import fcntl

    descriptor = os.open(output, os.O_RDONLY)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError("Output directory is in use") from None
        yield
    finally:
        os.close(descriptor)


class MigrationTarget:
    """A fresh SQLite file or empty PostgreSQL database, written only through contracts."""

    checks: tuple[str, ...] = CHECKS

    def __init__(self, conn: Any, dialect: Literal["sqlite", "postgres"], name: str) -> None:
        self.conn, self.dialect, self.name = conn, dialect, name
        self.store = RecordingStore(conn)
        self.expected = Expectations(set(), booleans_as_int=dialect == "sqlite")
        self.products: dict[str, str] = {}
        self.repos: dict[str, str] = {}
        self.product_repos: dict[tuple[str, str, str], str] = {}

    @classmethod
    def sqlite(cls, path: Path) -> MigrationTarget:
        path = path.resolve()
        with path.open("xb"):
            pass
        return cls(sqlite3.connect(path, isolation_level=None), "sqlite", str(path))

    @classmethod
    def postgres(cls, dsn: str) -> MigrationTarget:
        import psycopg

        conn = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
        return cls(conn, "postgres", conn.info.dbname)

    def table(self, name: str) -> str:
        return f'traust_storage."{name}"' if self.dialect == "postgres" else f'"{name}"'

    def initialize(self) -> None:
        if self.dialect == "postgres":
            if not self.conn.execute(
                "SELECT pg_try_advisory_lock(hashtext('traust:artifact-migration'))"
            ).fetchone()[0]:
                raise TargetInUse("Another migration is using this database")
            if self.conn.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' "
                "AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S','f'))"
            ).fetchone()[0]:
                raise TargetNotEmpty(
                    "Target must be an empty dedicated database; nothing was reset"
                )
        self.store.migrate()
        if self.dialect == "postgres":
            self.expected.json_columns = set(
                self.conn.execute(
                    "SELECT table_name, column_name FROM information_schema.columns "
                    "WHERE table_schema='traust_storage' AND data_type IN ('json','jsonb')"
                ).fetchall()
            )

    def register_repository(self, slug: str, url: str, ref: str) -> str:
        if (slug, url, ref) not in self.product_repos:
            if slug not in self.products:
                self.products[slug] = self.store.register_product(slug)
            if url not in self.repos:
                self.repos[url] = self.store.register_repo(url)
            self.product_repos[slug, url, ref] = self.store.register_product_repo(
                self.products[slug], self.repos[url], ref
            )
        return self.product_repos[slug, url, ref]

    def ingest(self, artifact: str, payload: bytes, binding: Binding) -> IngestResult:
        saved = self.store.ingest(artifact, payload, binding)
        if saved.digest != hashlib.sha256(payload).hexdigest():
            raise RuntimeError("Stored evidence digest differs from original bytes")
        if not saved.already_bound:
            self.expected.add(
                saved.binding_id,
                saved.digest,
                artifact,
                len(payload),
                binding,
                self.store.projected,
            )
        return saved

    def check_healthy(self) -> None:
        idle = (
            not self.conn.in_transaction
            if self.dialect == "sqlite"
            else not self.conn.closed and self.conn.info.transaction_status == 0
        )
        if not idle:
            raise RuntimeError("Database unavailable or record rollback failed")
        self.conn.execute("SELECT 1")

    def select(self, sql: str) -> Iterator[tuple[Any, ...]]:
        if self.dialect == "sqlite":
            yield from self.conn.execute(sql)
            return
        with self.conn.transaction(), self.conn.cursor(name="migration_verify") as cursor:
            cursor.execute(sql)
            yield from cursor

    def counts(self) -> dict[str, int]:
        if self.dialect == "sqlite":
            names = {
                table
                for (table,) in self.conn.execute(
                    "SELECT m.name FROM sqlite_schema m JOIN pragma_table_info(m.name) c "
                    "WHERE m.type='table' AND c.name='binding_id'"
                )
            }
        else:
            names = {
                table
                for (table,) in self.conn.execute(
                    "SELECT c.table_name FROM information_schema.columns c "
                    "JOIN information_schema.tables t USING (table_schema, table_name) "
                    "WHERE c.table_schema='traust_storage' AND c.column_name='binding_id' "
                    "AND t.table_type='BASE TABLE'"
                )
            }
        return {
            name: self.conn.execute(f"SELECT count(*) FROM {self.table(name)}").fetchone()[0]
            for name in sorted(names | {"artifact_evidence"})
        }

    def reconcile(self) -> tuple[dict[str, int], dict[str, int]]:
        expected, actual = self.expected.counts(), self.counts()
        if any(actual.get(t, 0) != expected.get(t, 0) for t in actual.keys() | expected.keys()):
            raise RuntimeError("Target row counts differ from verified artifact projections")
        self.expected.verify(self.select, self.table)
        return expected, actual

    def close(self) -> None:
        self.conn.close()
