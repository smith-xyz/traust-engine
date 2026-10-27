"""Typed failures for the toolchain's database wiring."""

from __future__ import annotations


class ScannerDatabaseUnavailable(RuntimeError):
    """A scanner's pinned vulnerability database is missing or unusable at its configured path.

    Raised before the scanner process starts, so a frozen scan against an empty or stale
    feeds-cache mount fails loudly instead of silently reporting zero findings.
    """
