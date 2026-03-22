"""Persistent storage layer for the Aliyun AVD crawler.

Responsibilities
----------------
* Persist raw :class:`~aliyun_crawler.models.RawAVDEntry` objects to JSON.
* Write enriched :class:`~aliyun_crawler.models.AVDCveEntry` objects to
  per-CVE YAML files (``<data_dir>/yaml/CVE-XXXX-XXXX.yaml``).
* Maintain an incremental-crawl state file (``<data_dir>/.state.json``) that
  tracks the timestamp of the *most recently seen* entry so subsequent runs
  can pass ``since`` to the crawler.
* Write a separate "commit-filtered" JSONL index of entries that have at least
  one GitHub commit / PR / issue link (``<data_dir>/has_commit.jsonl``).

Directory layout::

    <data_dir>/
        .state.json          – incremental crawl state
        raw/                 – raw RawAVDEntry JSON files
            CVE-2024-12345.json
            ...
        yaml/                – enriched AVDCveEntry YAML files
            CVE-2024-12345.yaml
            ...
        has_commit.jsonl     – newline-delimited JSON index of commit-linked entries
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from aliyun_crawler.models import AVDCveEntry, RawAVDEntry

logger = logging.getLogger(__name__)

_STATE_FILE = ".state.json"
_HAS_COMMIT_FILE = "has_commit.jsonl"
_STATE_VERSION = 2


class CrawlStorage:
    """File-system storage for crawled CVE data with incremental-state tracking.

    Args:
        data_dir: Root directory for all output.  Created on first use.
    """

    def __init__(self, data_dir: str = "./output/aliyun_cve") -> None:
        self.root = Path(data_dir)
        self.raw_dir = self.root / "raw"
        self.yaml_dir = self.root / "yaml"
        self._ensure_dirs()

    # ------------------------------------------------------------------
    # Directory management
    # ------------------------------------------------------------------

    def _ensure_dirs(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(exist_ok=True)
        self.yaml_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # Incremental-crawl state
    # ------------------------------------------------------------------

    def _now_iso(self) -> str:
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _new_state(self) -> dict[str, Any]:
        now = self._now_iso()
        return {
            "version": _STATE_VERSION,
            "schema": "crawl-state-v2",
            "updated_at": now,
            "stage1": {
                "incremental": {
                    "last_seen_date": None,
                    "last_seen_cve": None,
                },
                "last_run": {
                    "run_started_at": None,
                    "run_finished_at": None,
                    "status": "idle",
                    "max_pages": None,
                    "page_concurrency": None,
                    "raw_saved": 0,
                },
                "totals": {
                    "runs": 0,
                    "raw_saved": 0,
                },
            },
            "stage2": {
                "last_run": {
                    "run_started_at": None,
                    "run_finished_at": None,
                    "status": "idle",
                    "mode": "raw_snapshot",
                    "input_raw_count": 0,
                    "accepted_yaml_count": 0,
                    "rejected_raw_count": 0,
                },
                "totals": {
                    "runs": 0,
                    "accepted_yaml_count": 0,
                },
            },
            "stage3": {
                "last_run": {
                    "run_started_at": None,
                    "run_finished_at": None,
                    "status": "idle",
                    "target_count": 0,
                    "annotated_count": 0,
                    "partial": False,
                },
                "totals": {
                    "runs": 0,
                    "annotated_count": 0,
                },
            },
        }

    def _backup_legacy_state(self, legacy_state: dict[str, Any]) -> Path:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup = self.root / f".state.legacy-{ts}.json"
        backup.write_text(
            json.dumps(legacy_state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return backup

    def _ensure_state_shape(self, state: dict[str, Any]) -> dict[str, Any]:
        base = self._new_state()

        def _merge(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
            for key, value in src.items():
                if (
                    key in dst
                    and isinstance(dst[key], dict)
                    and isinstance(value, dict)
                ):
                    _merge(dst[key], value)
                else:
                    dst[key] = value
            return dst

        merged = _merge(base, state)
        merged["version"] = _STATE_VERSION
        merged["schema"] = "crawl-state-v2"
        merged["updated_at"] = self._now_iso()
        return merged

    def _migrate_if_needed(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("version") == _STATE_VERSION and "stage1" in state:
            return self._ensure_state_shape(state)

        legacy_like = bool(state) and "stage1" not in state
        if legacy_like:
            backup = self._backup_legacy_state(state)
            logger.info("Backed up legacy state to %s", backup)
            migrated = self._new_state()
            migrated["stage1"]["incremental"]["last_seen_date"] = state.get(
                "last_seen_date"
            )
            migrated["stage1"]["incremental"]["last_seen_cve"] = state.get(
                "last_seen_cve"
            )
            migrated["legacy_snapshot"] = state
            self.save_state(migrated)
            logger.info("Migrated state file to v2 schema")
            return migrated

        fresh = self._new_state()
        self.save_state(fresh)
        return fresh

    def load_state(self) -> dict[str, Any]:
        """Load the persisted crawl state dict."""
        path = self.root / _STATE_FILE
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return self._migrate_if_needed(data)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not load state file: %s", exc)
        return self._migrate_if_needed({})

    def save_state(self, state: dict[str, Any]) -> None:
        """Persist the crawl state dict."""
        path = self.root / _STATE_FILE
        path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")

    def get_last_seen_date(self) -> Optional[str]:
        """Return the ISO date string of the most recently crawled entry, or None."""
        state = self.load_state()
        return state.get("stage1", {}).get("incremental", {}).get("last_seen_date")

    def mark_stage1_start(self, *, max_pages: int, page_concurrency: int) -> None:
        state = self.load_state()
        now = self._now_iso()
        stage = state["stage1"]["last_run"]
        stage.update(
            {
                "run_started_at": now,
                "run_finished_at": None,
                "status": "running",
                "max_pages": max_pages,
                "page_concurrency": page_concurrency,
                "raw_saved": 0,
            }
        )
        state["updated_at"] = now
        self.save_state(state)

    def mark_stage1_end(self, *, status: str = "completed") -> None:
        state = self.load_state()
        now = self._now_iso()
        stage = state["stage1"]["last_run"]
        stage["run_finished_at"] = now
        stage["status"] = status
        state["stage1"]["totals"]["runs"] += 1
        state["updated_at"] = now
        self.save_state(state)

    def mark_stage2_summary(
        self, *, input_raw_count: int, accepted_yaml_count: int
    ) -> None:
        state = self.load_state()
        now = self._now_iso()
        state["stage2"]["last_run"] = {
            "run_started_at": now,
            "run_finished_at": now,
            "status": "completed",
            "mode": "raw_snapshot",
            "input_raw_count": input_raw_count,
            "accepted_yaml_count": accepted_yaml_count,
            "rejected_raw_count": max(0, input_raw_count - accepted_yaml_count),
        }
        state["stage2"]["totals"]["runs"] += 1
        state["stage2"]["totals"]["accepted_yaml_count"] += accepted_yaml_count
        state["updated_at"] = now
        self.save_state(state)

    def mark_stage3_summary(self, *, target_count: int, annotated_count: int) -> None:
        state = self.load_state()
        now = self._now_iso()
        partial = annotated_count < target_count
        state["stage3"]["last_run"] = {
            "run_started_at": now,
            "run_finished_at": now,
            "status": "completed",
            "target_count": target_count,
            "annotated_count": annotated_count,
            "partial": partial,
        }
        state["stage3"]["totals"]["runs"] += 1
        state["stage3"]["totals"]["annotated_count"] += annotated_count
        state["updated_at"] = now
        self.save_state(state)

    def update_last_seen_date(self, entry: RawAVDEntry) -> None:
        """Update stage1 incremental bookmark and counters for a saved raw entry."""
        ref_date = entry.modified_date or entry.crawled_at
        if ref_date is None:
            return
        state = self.load_state()
        current = state["stage1"]["incremental"].get("last_seen_date")
        new_val = ref_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        if current is None or new_val > current:
            state["stage1"]["incremental"]["last_seen_date"] = new_val
            state["stage1"]["incremental"]["last_seen_cve"] = entry.cve_id

        state["stage1"]["last_run"]["raw_saved"] += 1
        state["stage1"]["totals"]["raw_saved"] += 1
        state["updated_at"] = self._now_iso()
        self.save_state(state)

    # ------------------------------------------------------------------
    # Raw entry persistence
    # ------------------------------------------------------------------

    def save_raw(self, entry: RawAVDEntry) -> Path:
        """Write *entry* as JSON to ``<data_dir>/raw/<CVE-ID>.json``.

        Existing files are overwritten (idempotent on re-crawl).
        """
        path = self.raw_dir / f"{entry.cve_id}.json"
        path.write_text(
            entry.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )
        logger.debug("Saved raw entry: %s", path)
        return path

    def load_raw(self, cve_id: str) -> Optional[RawAVDEntry]:
        """Load a previously-saved raw entry by CVE ID, or return *None*."""
        path = self.raw_dir / f"{cve_id}.json"
        if not path.exists():
            return None
        try:
            return RawAVDEntry.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Could not load raw entry %s: %s", cve_id, exc)
            return None

    def raw_exists(self, cve_id: str) -> bool:
        return (self.raw_dir / f"{cve_id}.json").exists()

    # ------------------------------------------------------------------
    # Enriched YAML persistence
    # ------------------------------------------------------------------

    def save_yaml(self, entry: AVDCveEntry) -> Path:
        """Write *entry* as YAML to ``<data_dir>/yaml/<CVE-ID>.yaml``."""
        path = self.yaml_dir / f"{entry.CVE}.yaml"
        doc = entry.to_yaml_dict()
        path.write_text(
            yaml.dump(
                doc, allow_unicode=True, default_flow_style=False, sort_keys=False
            ),
            encoding="utf-8",
        )
        logger.debug("Saved YAML entry: %s", path)
        return path

    def save_yaml_to_subdir(self, entry: AVDCveEntry, subdir: str) -> Path:
        """Write *entry* as YAML to ``<data_dir>/<subdir>/<CVE-ID>.yaml``."""
        safe = subdir.strip().strip("/")
        if not safe:
            return self.save_yaml(entry)

        out_dir = self.root / safe
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{entry.CVE}.yaml"
        doc = entry.to_yaml_dict()
        path.write_text(
            yaml.dump(
                doc, allow_unicode=True, default_flow_style=False, sort_keys=False
            ),
            encoding="utf-8",
        )
        logger.debug("Saved YAML entry to subdir: %s", path)
        return path

    def load_yaml(self, cve_id: str) -> Optional[AVDCveEntry]:
        """Load a previously-saved enriched entry by CVE ID, or return *None*."""
        path = self.yaml_dir / f"{cve_id}.yaml"
        if not path.exists():
            return None
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            return AVDCveEntry(**doc)
        except Exception as exc:
            logger.error("Could not load YAML entry %s: %s", cve_id, exc)
            return None

    def yaml_exists(self, cve_id: str) -> bool:
        return (self.yaml_dir / f"{cve_id}.yaml").exists()

    # ------------------------------------------------------------------
    # Commit-linked index
    # ------------------------------------------------------------------

    def append_has_commit(self, entry: RawAVDEntry) -> None:
        """Append a minimal JSON record for *entry* to ``has_commit.jsonl``.

        Only entries with at least one ``patch_url`` should be written here.
        """
        if not entry.patch_urls:
            return
        path = self.root / _HAS_COMMIT_FILE
        record = {
            "cve_id": entry.cve_id,
            "patch_urls": entry.patch_urls,
            "severity": entry.severity,
            "cvss_score": entry.cvss_score,
            "cwe_id": entry.cwe_id,
            "modified_date": (
                entry.modified_date.strftime("%Y-%m-%d")
                if entry.modified_date
                else None
            ),
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def load_has_commit_index(self) -> list[dict[str, Any]]:
        """Return all records from the commit-linked index."""
        path = self.root / _HAS_COMMIT_FILE
        if not path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return records

    # ------------------------------------------------------------------
    # Batch helpers
    # ------------------------------------------------------------------

    def process_and_store(self, entry: RawAVDEntry) -> AVDCveEntry:
        """Save *entry* as raw JSON, build an :class:`AVDCveEntry`, save as YAML,
        update the commit index, and advance the incremental-state timestamp.

        Returns the created :class:`AVDCveEntry`.
        """
        self.save_raw(entry)
        cve_entry = AVDCveEntry.from_raw(entry)
        self.save_yaml(cve_entry)
        if entry.patch_urls:
            self.append_has_commit(entry)
        self.update_last_seen_date(entry)
        return cve_entry

    def list_yaml_cve_ids(self) -> list[str]:
        """Return all CVE IDs for which a YAML file exists."""
        return [p.stem for p in sorted(self.yaml_dir.glob("CVE-*.yaml"))]

    def list_raw_cve_ids(self) -> list[str]:
        """Return all CVE IDs for which a raw JSON file exists."""
        return [p.stem for p in sorted(self.raw_dir.glob("CVE-*.json"))]
