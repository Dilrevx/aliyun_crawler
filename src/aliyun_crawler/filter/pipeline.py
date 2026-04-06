"""Chainable filter pipeline for :class:`~aliyun_crawler.models.RawAVDEntry`.

Usage example::

    pipeline = FilterPipeline()

    # Keep only entries whose CWE is NOT CWE-202
    pipeline.exclude(lambda e: e.cwe_id == "CWE-202")

    # Keep only entries with at least one GitHub commit reference
    pipeline.require(lambda e: bool(e.patch_urls))

    for entry in pipeline.apply(raw_entries):
        ...

Multiple callbacks are composed with AND semantics: an entry must pass **all**
registered callbacks to appear in the output.

The :meth:`register` method is the generic hook; :meth:`require` and
:meth:`exclude` are convenience wrappers.  All callbacks are stored as a
singly-linked chain so new callbacks can be prepended or appended at runtime.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable
from typing import Optional

from aliyun_crawler.models import RawAVDEntry

logger = logging.getLogger(__name__)

# A filter callback: returns True to keep the entry, False to drop it.
FilterCallback = Callable[[RawAVDEntry], bool]


class _FilterNode:
    """Single node in the callback chain."""

    def __init__(self, callback: FilterCallback, name: str) -> None:
        self.callback = callback
        self.name = name
        self.next: Optional["_FilterNode"] = None


class FilterPipeline:
    """Chainable, reloadable filter pipeline for :class:`RawAVDEntry` objects.

    Callbacks are stored as a linked list, enabling O(1) prepend / append and
    easy runtime removal by name.
    """

    def __init__(self) -> None:
        self._head: Optional[_FilterNode] = None
        self._tail: Optional[_FilterNode] = None
        self._count: int = 0

    # ------------------------------------------------------------------
    # Registration API
    # ------------------------------------------------------------------

    def register(self, callback: FilterCallback, *, name: str = "") -> "FilterPipeline":
        """Append *callback* to the end of the filter chain.

        Args:
            callback: A callable ``(RawAVDEntry) -> bool``; return *True* to
                      keep the entry, *False* to drop it.
            name: Optional label used for logging and :meth:`remove`.

        Returns:
            *self* for fluent chaining.
        """
        node = _FilterNode(callback, name or f"filter_{self._count}")
        if self._tail is None:
            self._head = self._tail = node
        else:
            self._tail.next = node
            self._tail = node
        self._count += 1
        return self

    def require(self, predicate: FilterCallback, *, name: str = "") -> "FilterPipeline":
        """Keep entries for which *predicate* returns *True*.

        Convenience alias for :meth:`register`.
        """
        return self.register(predicate, name=name or f"require_{self._count}")

    def exclude(self, predicate: FilterCallback, *, name: str = "") -> "FilterPipeline":
        """Drop entries for which *predicate* returns *True*.

        Inverts the predicate before registering it.
        """
        return self.register(
            lambda e, p=predicate: not p(e),
            name=name or f"exclude_{self._count}",
        )

    def exclude_cwe(self, *cwe_ids: str) -> "FilterPipeline":
        """Drop entries whose :attr:`~RawAVDEntry.cwe_id` is in *cwe_ids*.

        Example::

            pipeline.exclude_cwe("CWE-202", "CWE-200")
        """
        cwe_set = set(cwe_ids)
        return self.exclude(
            lambda e: e.cwe_id in cwe_set,
            name=f"exclude_cwe({'|'.join(cwe_ids)})",
        )

    def require_cwe(self, *cwe_ids: str) -> "FilterPipeline":
        """Keep only entries whose CWE is in *cwe_ids*."""
        cwe_set = set(cwe_ids)
        return self.require(
            lambda e: e.cwe_id in cwe_set,
            name=f"require_cwe({'|'.join(cwe_ids)})",
        )

    def require_patch_url(self) -> "FilterPipeline":
        """Keep only entries that have at least one resolved patch URL (commit/PR/issue)."""
        return self.require(
            lambda e: bool(e.patch_urls),
            name="require_patch_url",
        )

    def require_severity(self, *severities: str) -> "FilterPipeline":
        """Keep only entries matching any of *severities* (case-insensitive)."""
        sev_set = {s.lower() for s in severities}
        return self.require(
            lambda e: e.severity.lower() in sev_set,
            name=f"require_severity({'|'.join(severities)})",
        )

    def require_cvss_min(self, min_score: float) -> "FilterPipeline":
        """Keep only entries with CVSS score >= *min_score*."""
        return self.require(
            lambda e: e.cvss_score is not None and e.cvss_score >= min_score,
            name=f"require_cvss_min({min_score})",
        )

    def require_cwe_pattern(self, pattern: str) -> "FilterPipeline":
        """Keep entries whose CWE ID matches *pattern* (regex)."""
        rx = re.compile(pattern, re.IGNORECASE)
        return self.require(
            lambda e: bool(rx.search(e.cwe_id)),
            name=f"require_cwe_pattern({pattern})",
        )

    def remove(self, name: str) -> bool:
        """Remove a named filter from the chain.

        Returns *True* if the filter was found and removed.
        """
        prev: Optional[_FilterNode] = None
        cur = self._head
        while cur is not None:
            if cur.name == name:
                if prev is None:
                    self._head = cur.next
                else:
                    prev.next = cur.next
                if cur.next is None:
                    self._tail = prev
                self._count -= 1
                logger.debug("Removed filter '%s'", name)
                return True
            prev = cur
            cur = cur.next
        logger.warning("Filter '%s' not found in pipeline", name)
        return False

    def clear(self) -> None:
        """Remove all registered filters."""
        self._head = self._tail = None
        self._count = 0

    def list_filters(self) -> list[str]:
        """Return names of all registered filters in order."""
        names: list[str] = []
        cur = self._head
        while cur is not None:
            names.append(cur.name)
            cur = cur.next
        return names

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def passes(self, entry: RawAVDEntry) -> bool:
        """Return *True* if *entry* passes all registered filters."""
        cur = self._head
        while cur is not None:
            try:
                if not cur.callback(entry):
                    logger.debug("Entry %s dropped by filter '%s'", entry.cve_id, cur.name)
                    return False
            except Exception as exc:
                logger.warning(
                    "Filter '%s' raised an exception for %s: %s — treating as drop",
                    cur.name,
                    entry.cve_id,
                    exc,
                )
                return False
            cur = cur.next
        return True

    def apply(self, entries: Iterable[RawAVDEntry]) -> Iterable[RawAVDEntry]:
        """Yield entries from *entries* that pass all registered filters."""
        for entry in entries:
            if self.passes(entry):
                yield entry

    def partition(
        self, entries: Iterable[RawAVDEntry]
    ) -> tuple[list[RawAVDEntry], list[RawAVDEntry]]:
        """Split *entries* into (passed, dropped) lists."""
        passed: list[RawAVDEntry] = []
        dropped: list[RawAVDEntry] = []
        for entry in entries:
            (passed if self.passes(entry) else dropped).append(entry)
        return passed, dropped

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return f"FilterPipeline(filters={self.list_filters()})"
