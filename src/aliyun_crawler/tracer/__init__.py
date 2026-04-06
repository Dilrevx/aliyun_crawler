from __future__ import annotations

import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_legacy_path = Path(__file__).resolve().parent.parent / "calltrace.py"
_spec = spec_from_file_location("aliyun_crawler._legacy_calltrace", _legacy_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Could not load legacy calltrace module from {_legacy_path}")
_legacy = module_from_spec(_spec)
sys.modules[_spec.name] = _legacy
_spec.loader.exec_module(_legacy)

CalltraceExplorer = _legacy.CalltraceExplorer
TokenStats = _legacy.TokenStats

__all__ = ["CalltraceExplorer", "TokenStats"]
