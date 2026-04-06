from __future__ import annotations

import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_legacy_path = Path(__file__).resolve().parent.parent / "crawler.py"
_spec = spec_from_file_location("aliyun_crawler._legacy_crawler", _legacy_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Could not load legacy crawler module from {_legacy_path}")
_legacy = module_from_spec(_spec)
sys.modules[_spec.name] = _legacy
_spec.loader.exec_module(_legacy)

AVDCrawler = _legacy.AVDCrawler
_BROWSER_ARGS = _legacy._BROWSER_ARGS
_STEALTH = _legacy._STEALTH
_USER_AGENT = _legacy._USER_AGENT

__all__ = ["AVDCrawler", "_BROWSER_ARGS", "_STEALTH", "_USER_AGENT"]
