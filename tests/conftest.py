"""Harness-engine test configuration — standalone package install."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# The suite must never read an operator's real configuration: point the config home at a
# private copy of the estate-neutral fixture.
_TEST_HOME = Path(tempfile.mkdtemp(prefix="traust-test-cfg-"))
shutil.copytree(_FIXTURES / "config", _TEST_HOME, dirs_exist_ok=True)
os.environ["TRAUST_CONFIG_HOME"] = str(_TEST_HOME)
