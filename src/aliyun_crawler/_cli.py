"""Installed-script entry-point wrapper.

Imports the Typer app from ``scripts/crawl_aliyun.py`` so it can be invoked
as ``crawl-aliyun`` after ``pip install -e .``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is on sys.path for editable / standalone invocations
_src = Path(__file__).resolve().parent.parent
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

# Re-export the Typer app so the entry-point [project.scripts] can find it.
# The actual implementation lives in scripts/crawl_aliyun.py to keep it runnable
# both as a script and as an installed command.
_scripts = _src.parent / "scripts"
if str(_scripts) not in sys.path:
    sys.path.insert(0, str(_scripts))

from crawl_aliyun import app  # noqa: E402  (dynamic path above)

__all__ = ["app"]
