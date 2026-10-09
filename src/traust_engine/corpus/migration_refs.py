"""Keep diagnostic provenance separate from executable artifact references."""

from __future__ import annotations

import re
import subprocess

from traust_engine.corpus.migration_discovery import DiscoveryError


def recorded_commit(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        raise DiscoveryError(
            "ambiguous_repository",
            "Artifact commit must be a bare full SHA; diagnostic provenance needs explicit repair",
        )
    return value


def repository_ref(value: str) -> str:
    if value == "":
        return value
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", value) or value.startswith("-"):
        raise DiscoveryError("ambiguous_repository", "Repository ref contains forbidden characters")
    result = subprocess.run(
        ["git", "check-ref-format", "--allow-onelevel", value], capture_output=True, check=False
    )
    if result.returncode:
        raise DiscoveryError("ambiguous_repository", "Repository ref fails Git reference syntax")
    return value
