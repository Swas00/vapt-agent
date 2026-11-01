"""Runs the jsdom UI suite (tests/frontend/ui.test.js) as part of `pytest`.

The app itself has no JS build step; Node + jsdom are dev-only and optional. Without them this test
is skipped (not failed), so a Python-only checkout still gets a green run:

    cd tests/frontend && npm install        # enables it
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FRONTEND = Path(__file__).parent / "frontend"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.skipif(not (FRONTEND / "node_modules" / "jsdom").exists(),
                    reason="jsdom not installed -- run `npm install` in tests/frontend")
def test_ui_suite_passes_in_jsdom():
    result = subprocess.run(["node", "--test", "ui.test.js"], cwd=FRONTEND, capture_output=True,
                            text=True, timeout=180)
    assert result.returncode == 0, (result.stdout[-4000:] + "\n" + result.stderr[-2000:])
