from __future__ import annotations

import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from vulndb_mirror.models import RawAVDEntry
from vulndb_mirror.storage.raw_models import (
    PageCheckpoint,
    PageGap,
    RawMeta,
    RawQueryResult,
    now_iso,
)

logger = logging.getLogger(__name__)


def _utc_today() -> str:
    return now_iso()[:10]


def _expand_neighbor_pages(pages: list[int], *, max_offset: int = 1) -> list[int]:
    out: set[int] = set()
    for page in pages:
        for offset in range(-max_offset, max_offset + 1):
            candidate = page + offset
            if candidate >= 1:
                out.add(candidate)
    return sorted(out)


class RawRepository(ABC):
    @abstractmethod
    def upsert_raw(self, entry: RawAVDEntry, *, page: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_raw(self, cve_id: str) -> Optional[RawAVDEntry]:
        raise NotImplementedError

    @abstractmethod
    def query_raw(
        self,
        *,
        modified_from: Optional[str],
        modified_to: Optional[str],
        page: int,
        page_size: int,
    ) -> RawQueryResult:
        raise NotImplementedError

    @abstractmethod
    def save_checkpoint(self, checkpoint: PageCheckpoint) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_checkpoints(self, *, status: Optional[str] = None) -> list[PageCheckpoint]:
        raise NotImplementedError

    @abstractmethod
    def get_gaps(self, *, max_page: int, include_failed: bool = True) -> list[PageGap]:
        raise NotImplementedError

    @abstractmethod
    def get_meta(self) -> RawMeta:
        raise NotImplementedError

    @abstractmethod
    def update_resume_page(self, page: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_cve_ids(self, *, pages: Optional[list[int]] = None) -> list[str]:
        raise NotImplementedError


class FileRawRepository(RawRepository):
    def __init__(self, data_dir: str) -> None:
        self.root = Path(data_dir)
        self.raw_dir = self.root / "raw"
        self.state_file = self.root / ".rawdb.state.json"
        self.root.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def _load_state(self) -> dict:
        if not self.state_file.exists():
            return {
                "updated_at": now_iso(),
                "last_seen_date": None,
                "last_seen_cve": None,
                "resumable_from_page": 1,
                "page_tracking_date": _utc_today(),
                "page_checkpoints": {},
                "page_cve_index": {},
            }
        try:
            state = json.loads(self.state_file.read_text(encoding="utf-8"))
            return self._normalize_page_tracking_state(state)
        except Exception:
            logger.warning("Failed to read state file, recreating: %s", self.state_file)
            return {
                "updated_at": now_iso(),
                "last_seen_date": None,
                "last_seen_cve": None,
                "resumable_from_page": 1,
                "page_tracking_date": _utc_today(),
                "page_checkpoints": {},
                "page_cve_index": {},
            }

    def _normalize_page_tracking_state(self, state: dict) -> dict:
        today = _utc_today()
        tracking_date = state.get("page_tracking_date")
        if tracking_date != today:
            # List pages are reverse-chronological and can drift daily.
            # Keep historical page<->CVE mapping and derive a resume hint window.
            last_seen_cve = state.get("last_seen_cve")
            page_index = state.get("page_cve_index") or {}
            anchor_pages: list[int] = []
            if last_seen_cve:
                for page_key, cves in page_index.items():
                    if not isinstance(cves, list):
                        continue
                    if last_seen_cve in cves:
                        try:
                            anchor_pages.append(int(page_key))
                        except (TypeError, ValueError):
                            continue

            resume_hint_pages = _expand_neighbor_pages(anchor_pages, max_offset=1)
            state["page_tracking_date"] = today
            state["resume_hint_pages"] = resume_hint_pages
            if resume_hint_pages:
                # Start from the earliest candidate page and re-crawl forward.
                state["resumable_from_page"] = min(resume_hint_pages)
            state["updated_at"] = now_iso()
            self._save_state(state)
        else:
            state.setdefault("page_checkpoints", {})
            state.setdefault("page_cve_index", {})
            state.setdefault("resumable_from_page", 1)
            state.setdefault("resume_hint_pages", [])
        return state

    def _save_state(self, state: dict) -> None:
        state["updated_at"] = now_iso()
        self._atomic_write_text(
            self.state_file,
            json.dumps(state, ensure_ascii=False, indent=2),
        )

    def _atomic_write_text(self, path: Path, content: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)

    def upsert_raw(self, entry: RawAVDEntry, *, page: int) -> None:
        path = self.raw_dir / f"{entry.cve_id}.json"
        self._atomic_write_text(
            path,
            entry.model_dump_json(indent=2, exclude_none=True),
        )

        state = self._load_state()
        ref = entry.modified_date or entry.crawled_at
        if ref is not None:
            new_val = ref.strftime("%Y-%m-%dT%H:%M:%SZ")
            current = state.get("last_seen_date")
            if current is None or new_val > current:
                state["last_seen_date"] = new_val
                state["last_seen_cve"] = entry.cve_id
        page_index = state.setdefault("page_cve_index", {})
        cve_list = page_index.setdefault(str(page), [])
        if entry.cve_id not in cve_list:
            cve_list.append(entry.cve_id)
        state["resumable_from_page"] = max(
            int(state.get("resumable_from_page", 1)), page + 1
        )
        self._save_state(state)

    def get_raw(self, cve_id: str) -> Optional[RawAVDEntry]:
        path = self.raw_dir / f"{cve_id}.json"
        if not path.exists():
            return None
        try:
            return RawAVDEntry.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("failed to parse raw %s: %s", cve_id, exc)
            return None

    def query_raw(
        self,
        *,
        modified_from: Optional[str],
        modified_to: Optional[str],
        page: int,
        page_size: int,
    ) -> RawQueryResult:
        items: list[RawAVDEntry] = []
        for raw_path in sorted(self.raw_dir.glob("CVE-*.json")):
            try:
                item = RawAVDEntry.model_validate_json(
                    raw_path.read_text(encoding="utf-8")
                )
            except Exception:
                continue

            md = item.modified_date.strftime("%Y-%m-%d") if item.modified_date else None
            if modified_from and md and md < modified_from:
                continue
            if modified_to and md and md > modified_to:
                continue
            items.append(item)

        items.sort(
            key=lambda x: (x.modified_date is None, x.modified_date),
            reverse=True,
        )
        total = len(items)
        start = (page - 1) * page_size
        end = start + page_size
        return RawQueryResult(
            page=page, page_size=page_size, total=total, items=items[start:end]
        )

    def save_checkpoint(self, checkpoint: PageCheckpoint) -> None:
        state = self._load_state()
        cps = state.setdefault("page_checkpoints", {})
        cps[str(checkpoint.page)] = checkpoint.model_dump()
        if checkpoint.status == "ok":
            state["resumable_from_page"] = max(
                int(state.get("resumable_from_page", 1)), checkpoint.page + 1
            )
        self._save_state(state)

    def list_checkpoints(self, *, status: Optional[str] = None) -> list[PageCheckpoint]:
        state = self._load_state()
        cps = []
        for key, value in state.get("page_checkpoints", {}).items():
            try:
                cp = PageCheckpoint.model_validate(value)
            except Exception:
                continue
            if status and cp.status != status:
                continue
            cps.append(cp)
        cps.sort(key=lambda x: x.page)
        return cps

    def get_gaps(self, *, max_page: int, include_failed: bool = True) -> list[PageGap]:
        cps = {cp.page: cp for cp in self.list_checkpoints()}
        missing_pages: list[int] = []
        failed_pages: list[int] = []
        for page in range(1, max_page + 1):
            cp = cps.get(page)
            if cp is None:
                missing_pages.append(page)
            elif include_failed and cp.status == "failed":
                failed_pages.append(page)
        return _compress_gaps(missing_pages, failed_pages)

    def get_meta(self) -> RawMeta:
        state = self._load_state()
        return RawMeta(
            updated_at=state.get("updated_at", now_iso()),
            last_seen_date=state.get("last_seen_date"),
            last_seen_cve=state.get("last_seen_cve"),
            resumable_from_page=int(state.get("resumable_from_page", 1)),
        )

    def update_resume_page(self, page: int) -> None:
        state = self._load_state()
        state["resumable_from_page"] = max(1, int(page))
        self._save_state(state)

    def list_cve_ids(self, *, pages: Optional[list[int]] = None) -> list[str]:
        if pages:
            state = self._load_state()
            page_index = state.get("page_cve_index", {})
            out: list[str] = []
            for page in pages:
                out.extend(page_index.get(str(page), []))
            return sorted(set(out))
        return sorted(p.stem for p in self.raw_dir.glob("CVE-*.json"))


class SqliteRawRepository(RawRepository):
    def __init__(self, sqlite_path: str) -> None:
        self.sqlite_path = sqlite_path
        Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_entries (
                    cve_id TEXT PRIMARY KEY,
                    modified_date TEXT,
                    page INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS page_checkpoints (
                    page INTEGER PRIMARY KEY,
                    status TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    has_next INTEGER NOT NULL,
                    error TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
                """
            )
            conn.commit()
        self._refresh_page_tracking_if_stale()

    def _refresh_page_tracking_if_stale(self) -> None:
        today = _utc_today()
        current = self._get_meta("page_tracking_date")
        if current == today:
            return
        last_seen_cve = self._get_meta("last_seen_cve")
        anchor_pages: list[int] = []
        if last_seen_cve:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT page FROM raw_entries WHERE cve_id=? ORDER BY page ASC",
                    (last_seen_cve,),
                ).fetchall()
            anchor_pages = [int(row["page"]) for row in rows if row["page"] is not None]
        resume_hint_pages = _expand_neighbor_pages(anchor_pages, max_offset=1)

        with self._connect() as conn:
            if resume_hint_pages:
                conn.execute(
                    "INSERT INTO raw_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ("resumable_from_page", str(min(resume_hint_pages))),
                )
                conn.execute(
                    "INSERT INTO raw_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ("resume_hint_pages", json.dumps(resume_hint_pages)),
                )
            conn.execute(
                "INSERT INTO raw_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("page_tracking_date", today),
            )
            conn.execute(
                "INSERT INTO raw_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("updated_at", now_iso()),
            )
            conn.commit()

    def _set_meta(self, key: str, value: Optional[str]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO raw_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            conn.commit()

    def _get_meta(self, key: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM raw_meta WHERE key=?", (key,)
            ).fetchone()
            return None if row is None else row["value"]

    def upsert_raw(self, entry: RawAVDEntry, *, page: int) -> None:
        self._refresh_page_tracking_if_stale()
        modified = (
            entry.modified_date.strftime("%Y-%m-%d") if entry.modified_date else None
        )
        payload = entry.model_dump_json(exclude_none=True)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO raw_entries(cve_id, modified_date, page, payload, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    modified_date=excluded.modified_date,
                    page=excluded.page,
                    payload=excluded.payload,
                    updated_at=excluded.updated_at
                """,
                (entry.cve_id, modified, page, payload, now_iso()),
            )
            conn.commit()

        ref = entry.modified_date or entry.crawled_at
        if ref is not None:
            new_val = ref.strftime("%Y-%m-%dT%H:%M:%SZ")
            current = self._get_meta("last_seen_date")
            if current is None or new_val > current:
                self._set_meta("last_seen_date", new_val)
                self._set_meta("last_seen_cve", entry.cve_id)
        self.update_resume_page(page + 1)

    def get_raw(self, cve_id: str) -> Optional[RawAVDEntry]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM raw_entries WHERE cve_id=?", (cve_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            return RawAVDEntry.model_validate_json(row["payload"])
        except Exception:
            return None

    def query_raw(
        self,
        *,
        modified_from: Optional[str],
        modified_to: Optional[str],
        page: int,
        page_size: int,
    ) -> RawQueryResult:
        where = []
        args: list[object] = []
        if modified_from:
            where.append("(modified_date IS NULL OR modified_date >= ?)")
            args.append(modified_from)
        if modified_to:
            where.append("(modified_date IS NULL OR modified_date <= ?)")
            args.append(modified_to)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""

        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(1) AS c FROM raw_entries {where_sql}",
                args,
            ).fetchone()["c"]
            offset = (page - 1) * page_size
            rows = conn.execute(
                f"""
                SELECT payload FROM raw_entries
                {where_sql}
                ORDER BY modified_date DESC, cve_id DESC
                LIMIT ? OFFSET ?
                """,
                [*args, page_size, offset],
            ).fetchall()

        items: list[RawAVDEntry] = []
        for row in rows:
            try:
                items.append(RawAVDEntry.model_validate_json(row["payload"]))
            except Exception:
                continue
        return RawQueryResult(
            page=page, page_size=page_size, total=int(total), items=items
        )

    def save_checkpoint(self, checkpoint: PageCheckpoint) -> None:
        self._refresh_page_tracking_if_stale()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO page_checkpoints(page, status, entry_count, has_next, error, updated_at)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(page) DO UPDATE SET
                    status=excluded.status,
                    entry_count=excluded.entry_count,
                    has_next=excluded.has_next,
                    error=excluded.error,
                    updated_at=excluded.updated_at
                """,
                (
                    checkpoint.page,
                    checkpoint.status,
                    checkpoint.entry_count,
                    1 if checkpoint.has_next else 0,
                    checkpoint.error,
                    checkpoint.updated_at,
                ),
            )
            conn.commit()
        if checkpoint.status == "ok":
            self.update_resume_page(checkpoint.page + 1)

    def list_checkpoints(self, *, status: Optional[str] = None) -> list[PageCheckpoint]:
        self._refresh_page_tracking_if_stale()
        sql = "SELECT * FROM page_checkpoints"
        args: list[object] = []
        if status:
            sql += " WHERE status=?"
            args.append(status)
        sql += " ORDER BY page ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [
            PageCheckpoint(
                page=row["page"],
                status=row["status"],
                entry_count=row["entry_count"],
                has_next=bool(row["has_next"]),
                error=row["error"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    def get_gaps(self, *, max_page: int, include_failed: bool = True) -> list[PageGap]:
        self._refresh_page_tracking_if_stale()
        cps = {cp.page: cp for cp in self.list_checkpoints()}
        missing_pages: list[int] = []
        failed_pages: list[int] = []
        for page in range(1, max_page + 1):
            cp = cps.get(page)
            if cp is None:
                missing_pages.append(page)
            elif include_failed and cp.status == "failed":
                failed_pages.append(page)
        return _compress_gaps(missing_pages, failed_pages)

    def get_meta(self) -> RawMeta:
        self._refresh_page_tracking_if_stale()
        updated = self._get_meta("updated_at") or now_iso()
        return RawMeta(
            updated_at=updated,
            last_seen_date=self._get_meta("last_seen_date"),
            last_seen_cve=self._get_meta("last_seen_cve"),
            resumable_from_page=int(self._get_meta("resumable_from_page") or "1"),
        )

    def update_resume_page(self, page: int) -> None:
        self._refresh_page_tracking_if_stale()
        self._set_meta("resumable_from_page", str(max(1, int(page))))
        self._set_meta("updated_at", now_iso())

    def list_cve_ids(self, *, pages: Optional[list[int]] = None) -> list[str]:
        self._refresh_page_tracking_if_stale()
        with self._connect() as conn:
            if pages:
                placeholders = ",".join("?" for _ in pages)
                rows = conn.execute(
                    (
                        "SELECT DISTINCT cve_id "
                        "FROM raw_entries "
                        f"WHERE page IN ({placeholders}) "
                        "ORDER BY cve_id ASC"
                    ),
                    pages,
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT cve_id FROM raw_entries ORDER BY cve_id ASC"
                ).fetchall()
        return [row["cve_id"] for row in rows]


class DualWriteRawRepository(RawRepository):
    def __init__(self, primary: RawRepository, secondary: RawRepository) -> None:
        self.primary = primary
        self.secondary = secondary

    def _dual_write(self, fn_name: str, *args, **kwargs) -> None:
        primary_error: Exception | None = None
        secondary_error: Exception | None = None

        try:
            getattr(self.primary, fn_name)(*args, **kwargs)
        except Exception as exc:
            primary_error = exc

        try:
            getattr(self.secondary, fn_name)(*args, **kwargs)
        except Exception as exc:
            secondary_error = exc

        if primary_error:
            if secondary_error:
                raise RuntimeError(
                    f"dual-write failed on both backends: {primary_error}; {secondary_error}"
                )
            logger.warning(
                "primary backend failed for %s, secondary succeeded: %s",
                fn_name,
                primary_error,
            )

    def upsert_raw(self, entry: RawAVDEntry, *, page: int) -> None:
        self._dual_write("upsert_raw", entry, page=page)

    def get_raw(self, cve_id: str) -> Optional[RawAVDEntry]:
        try:
            result = self.primary.get_raw(cve_id)
            if result is not None:
                return result
        except Exception:
            pass
        return self.secondary.get_raw(cve_id)

    def query_raw(
        self,
        *,
        modified_from: Optional[str],
        modified_to: Optional[str],
        page: int,
        page_size: int,
    ) -> RawQueryResult:
        try:
            return self.primary.query_raw(
                modified_from=modified_from,
                modified_to=modified_to,
                page=page,
                page_size=page_size,
            )
        except Exception:
            return self.secondary.query_raw(
                modified_from=modified_from,
                modified_to=modified_to,
                page=page,
                page_size=page_size,
            )

    def save_checkpoint(self, checkpoint: PageCheckpoint) -> None:
        self._dual_write("save_checkpoint", checkpoint)

    def list_checkpoints(self, *, status: Optional[str] = None) -> list[PageCheckpoint]:
        try:
            return self.primary.list_checkpoints(status=status)
        except Exception:
            return self.secondary.list_checkpoints(status=status)

    def get_gaps(self, *, max_page: int, include_failed: bool = True) -> list[PageGap]:
        try:
            return self.primary.get_gaps(
                max_page=max_page, include_failed=include_failed
            )
        except Exception:
            return self.secondary.get_gaps(
                max_page=max_page, include_failed=include_failed
            )

    def get_meta(self) -> RawMeta:
        try:
            return self.primary.get_meta()
        except Exception:
            return self.secondary.get_meta()

    def update_resume_page(self, page: int) -> None:
        self._dual_write("update_resume_page", page)

    def list_cve_ids(self, *, pages: Optional[list[int]] = None) -> list[str]:
        try:
            result = self.primary.list_cve_ids(pages=pages)
            if result:
                return result
        except Exception:
            pass
        return self.secondary.list_cve_ids(pages=pages)


def _compress_pages(pages: list[int], reason: str) -> list[PageGap]:
    if not pages:
        return []
    pages = sorted(set(pages))
    chunks: list[PageGap] = []
    start = pages[0]
    prev = pages[0]
    for p in pages[1:]:
        if p == prev + 1:
            prev = p
            continue
        chunks.append(PageGap(start_page=start, end_page=prev, reason=reason))
        start = p
        prev = p
    chunks.append(PageGap(start_page=start, end_page=prev, reason=reason))
    return chunks


def _compress_gaps(missing_pages: list[int], failed_pages: list[int]) -> list[PageGap]:
    gaps = _compress_pages(missing_pages, "missing")
    gaps.extend(_compress_pages(failed_pages, "failed"))
    gaps.sort(key=lambda g: (g.start_page, g.reason))
    return gaps
