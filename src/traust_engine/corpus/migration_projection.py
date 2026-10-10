"""Record the rows contracts writes and verify them against the target in one pass."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Hashable, Iterable, Mapping
from decimal import Decimal
from typing import Any

from traust_contracts.v1.storage import Binding, Store
from traust_contracts.v1.storage.store import SQLValue

INSERT = re.compile(r"INSERT INTO (?:traust_storage\.)?(\w+)\s*\((.*?)\)\s*VALUES", re.S)
BINDING_COLUMNS = (
    "binding_id, artifact_digest, artifact_name, scope_id, subject_id, run_id, layer_id, "
    "supersedes_binding_id, bound_at, artifact_role, product_repo_id, commit_sha"
)


class ProjectionMismatch(ValueError):
    """The database did not retain exactly the authored projection's values."""


def _row_key(value: Any) -> Hashable:
    if isinstance(value, dict):
        return "object", tuple((key, _row_key(item)) for key, item in sorted(value.items()))
    if isinstance(value, list):
        return "array", tuple(map(_row_key, value))
    if isinstance(value, bool):
        return "boolean", value
    if isinstance(value, (int, float)):
        # JSONB may render 1.0 as 1; lexical precision remains in exact artifact evidence.
        return "number", Decimal(str(value))
    return type(value).__name__, value


def _fingerprint(row: Mapping[str, Any]) -> bytes:
    return hashlib.blake2b(repr(_row_key(dict(row))).encode(), digest_size=16).digest()


class RecordingStore(Store):  # type: ignore[misc]  # traust-contracts ships no py.typed
    """Contracts' store that keeps each projection row it inserted, and refuses dropped rows."""

    def __init__(self, conn: Any) -> None:
        super().__init__(conn)
        self.projected: list[tuple[str, dict[str, SQLValue]]] = []
        self._recording = False

    def _execute(self, sql: str, values: Mapping[str, SQLValue] | None = None) -> Any:
        cursor = super()._execute(sql, values)
        if self._recording and values is not None and (match := INSERT.match(sql.strip())):
            if {column.strip() for column in match[2].split(",")} != set(values):
                raise ProjectionMismatch("Unsupported projection column mapping")
            if cursor.rowcount != 1:
                raise ProjectionMismatch(f"Projection row was not stored in {match[1]}")
            self.projected.append((match[1], dict(values)))
        return cursor

    def _project(
        self, artifact: str, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        self.projected.clear()
        self._recording = True
        try:
            super()._project(artifact, document, digest, binding_id_value)
        finally:
            self._recording = False


class Expectations:
    """What the target must hold after the import: evidence, bindings, and projection rows."""

    def __init__(self, json_columns: set[tuple[str, str]], booleans_as_int: bool) -> None:
        self.json_columns = json_columns
        self.booleans_as_int = booleans_as_int
        self.evidence: dict[str, int] = {}
        self.bindings: dict[str, tuple[str, str, Binding]] = {}
        self.columns: dict[str, tuple[str, ...]] = {}
        self.rows: dict[str, Counter[tuple[str, bytes]]] = defaultdict(Counter)

    def add(
        self,
        binding_id: str,
        digest: str,
        artifact: str,
        size: int,
        binding: Binding,
        rows: Iterable[tuple[str, dict[str, SQLValue]]],
    ) -> None:
        self.evidence[digest] = size
        self.bindings[binding_id] = (digest, artifact, binding)
        for table, row in rows:
            columns = self.columns.setdefault(table, tuple(sorted(row)))
            if columns != tuple(sorted(row)):
                raise ProjectionMismatch(f"Inconsistent projection columns in {table}")
            self.rows[table][binding_id, _fingerprint(self._normalize(table, row))] += 1

    def _normalize(self, table: str, row: dict[str, SQLValue]) -> dict[str, Any]:
        return {
            key: json.loads(value)
            if isinstance(value, str) and (table, key) in self.json_columns
            else int(value)
            if self.booleans_as_int and isinstance(value, bool)
            else value
            for key, value in row.items()
        }

    def counts(self) -> dict[str, int]:
        return {
            "artifact_evidence": len(self.evidence),
            "artifact_binding": len(self.bindings),
            **{table: sum(rows.values()) for table, rows in self.rows.items()},
        }

    def verify(self, select: Any, table: Any) -> None:
        """Stream each table once; ``select(sql)`` yields rows, ``table(name)`` quotes a name."""
        evidence = dict(select(f"SELECT digest, byte_size FROM {table('artifact_evidence')}"))
        if evidence != self.evidence:
            raise ProjectionMismatch("Stored evidence pointers differ from original bytes")
        stored = (
            Store._binding_record(row[0], tuple(row[1:]))
            for row in select(f"SELECT {BINDING_COLUMNS} FROM {table('artifact_binding')}")
        )
        if {
            record.binding_id: (record.artifact_digest, record.artifact_name, record.binding)
            for record in stored
        } != self.bindings:
            raise ProjectionMismatch("Stored bindings differ from declared context")
        for name, columns in self.columns.items():
            selected = ", ".join(f'"{column}"' for column in columns)
            key = columns.index("binding_id")
            actual: Counter[tuple[str, bytes]] = Counter(
                (values[key], _fingerprint(dict(zip(columns, values, strict=True))))
                for values in select(f"SELECT {selected} FROM {table(name)}")
            )
            if actual != self.rows[name]:
                diff = (actual - self.rows[name]) + (self.rows[name] - actual)
                differing = sorted({binding for binding, _ in diff})
                raise ProjectionMismatch(
                    f"Projection values or multiplicity differ in {name} for {differing[:3]}"
                )
