"""Bounded CPU-only validation; workers never own database connections or decisions."""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import Iterator
from concurrent.futures import Future, ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from typing import Any

from traust_engine.corpus.migration_validation import MigrationValidationError, validate_artifact


def validate_source(task: tuple[str, str, str]) -> list[dict[str, Any]]:
    name, family, expected = task
    path = Path(name)
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise RuntimeError("Source changed after inventory")
    try:
        validate_artifact(path, family, collect_all=True, payload=payload)
    except MigrationValidationError as error:
        return [failure.to_dict() for failure in error.issues]
    return []


def validation_results(
    tasks: Iterator[tuple[str, str, str]], workers: int
) -> Iterator[tuple[tuple[str, str, str], list[dict[str, Any]]]]:
    if workers == 1:
        for task in tasks:
            yield task, validate_source(task)
        return
    with ProcessPoolExecutor(max_workers=workers, mp_context=get_context("spawn")) as pool:
        pending: deque[tuple[tuple[str, str, str], Future[list[dict[str, Any]]]]] = deque()
        for _ in range(workers * 2):
            task = next(tasks, None)
            if task is None:
                break
            pending.append((task, pool.submit(validate_source, task)))
        while pending:
            task, future = pending.popleft()
            yield task, future.result()
            following = next(tasks, None)
            if following is not None:
                pending.append((following, pool.submit(validate_source, following)))
