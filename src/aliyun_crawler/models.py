"""Data models for the Aliyun AVD crawler.

:class:`RawAVDEntry`  – intermediate struct populated by the crawler from HTML.
:class:`AVDCveEntry`  – final output struct that serialises to the route-hacker
                        YAML schema (matches CVE-2021-22113.yaml structure).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Intermediate (raw) HTML-parsed model
# ---------------------------------------------------------------------------


class RawAVDEntry(BaseModel):
    """Raw data scraped from the AVD list + detail pages before normalisation."""

    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")
    title: str = Field(default="", description="Vulnerability title (Chinese/English)")
    description: str = Field(default="", description="Full CVE description")
    severity: str = Field(default="", description="Severity label: 低危/中危/高危/严重")
    cvss_score: Optional[float] = Field(default=None, description="CVSS v3 base score")
    cvss_vector: str = Field(default="", description="CVSS v3 vector string")
    cwe_id: str = Field(default="", description="Primary CWE, e.g. CWE-79")
    cwe_description: str = Field(default="", description="CWE description text")
    published_date: Optional[datetime] = Field(default=None, description="NVD publish date")
    modified_date: Optional[datetime] = Field(default=None, description="NVD last-modified date")
    affected_software: list[str] = Field(
        default_factory=list,
        description="CPE or human-readable affected software list",
    )
    references: list[str] = Field(
        default_factory=list,
        description="All reference URLs from the detail page",
    )
    patch_urls: list[str] = Field(
        default_factory=list,
        description="Subset of references that look like GitHub commits / PRs / issues",
    )
    detail_url: str = Field(default="", description="Full URL of the detail page")

    # ---- incremental bookkeeping --------------------------------------------
    crawled_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Calltrace models (mirrors CVE-2021-22113.yaml schema)
# ---------------------------------------------------------------------------


class TraceFrame(BaseModel):
    """A single frame in a before/after call trace."""

    depth: int = Field(..., ge=0)
    file: str = Field(..., description="Repo-relative file path")
    method: str = Field(default="", description="Method / function name")
    start_line: int = Field(default=0, ge=0)
    end_line: int = Field(default=0, ge=0)


class PatchMethod(BaseModel):
    """One patched method location (semanticised equivalent of the tuple format)."""

    file: str
    method: str
    start_line: int
    end_line: int


class CallTraceData(BaseModel):
    """Full before/after calltrace structure."""

    before_traces: list[list[TraceFrame]] = Field(default_factory=list)
    after_traces: list[list[TraceFrame]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Final output model
# ---------------------------------------------------------------------------


class AVDCveEntry(BaseModel):
    """Output CVE entry serialised to route-hacker YAML schema.

    Field names intentionally match the existing YAML keys so that
    :func:`to_yaml_dict` produces a drop-in compatible file.
    """

    # ---- Core identifiers --------------------------------------------------
    CVE: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")
    CVEDescription: str = Field(default="", description="Full vulnerability description")
    CWE: str = Field(default="", description="Primary CWE identifier, e.g. CWE-79")
    CWEDescription: str = Field(default="", description="CWE category description")

    # ---- Severity / scoring -------------------------------------------------
    severity: str = Field(default="", description="Severity label")
    cvss_score: Optional[float] = Field(default=None)
    cvss_vector: str = Field(default="")

    # ---- Dates --------------------------------------------------------------
    published_date: Optional[str] = Field(default=None, description="ISO-8601 publish date string")
    modified_date: Optional[str] = Field(
        default=None, description="ISO-8601 last-modified date string"
    )

    # ---- Affected software --------------------------------------------------
    affected_software: list[str] = Field(default_factory=list)

    # ---- Patch / commit references ------------------------------------------
    patch_url: str = Field(
        default="",
        description="Primary GitHub commit URL (first resolved commit)",
    )
    patch_urls: list[str] = Field(
        default_factory=list,
        description="All resolved patch commit URLs",
    )
    vul_version: str = Field(
        default="",
        description="Git commit hash of the vulnerable version (parent of patch)",
    )

    # ---- Patched methods (semantic k-v replacing the old tuple format) ------
    patch_method_before: list[PatchMethod] = Field(
        default_factory=list,
        description="Methods in the state before the patch",
    )
    patch_method_after: list[PatchMethod] = Field(
        default_factory=list,
        description="Methods in the state after the patch",
    )

    # ---- Calltrace (filled in by LLM analysis) -----------------------------
    CallTrace: Optional[CallTraceData] = Field(
        default=None,
        description="LLM-generated before/after calltrace from data entry to patch point",
    )

    # ---- Source / sink hints ------------------------------------------------
    source: list[str] = Field(default_factory=list, description="Identified data sources")
    sink: list[str] = Field(default_factory=list, description="Identified data sinks")

    # ---- Free-form analysis -------------------------------------------------
    reason: str = Field(
        default="",
        description="Human/LLM narrative explaining the vulnerability and patch",
    )

    # ---- Raw references (preserved for downstream use) ----------------------
    references: list[str] = Field(default_factory=list)
    detail_url: str = Field(default="")
    crawled_at: Optional[str] = Field(default=None)

    # -------------------------------------------------------------------------

    @classmethod
    def from_raw(cls, raw: RawAVDEntry) -> "AVDCveEntry":
        """Create a minimal :class:`AVDCveEntry` from a :class:`RawAVDEntry`."""
        patch_url = raw.patch_urls[0] if raw.patch_urls else ""
        return cls(
            CVE=raw.cve_id,
            CVEDescription=raw.description,
            CWE=raw.cwe_id,
            CWEDescription=raw.cwe_description,
            severity=raw.severity,
            cvss_score=raw.cvss_score,
            cvss_vector=raw.cvss_vector,
            published_date=(
                raw.published_date.strftime("%Y-%m-%d") if raw.published_date else None
            ),
            modified_date=(raw.modified_date.strftime("%Y-%m-%d") if raw.modified_date else None),
            affected_software=raw.affected_software,
            patch_url=patch_url,
            patch_urls=raw.patch_urls,
            references=raw.references,
            detail_url=raw.detail_url,
            crawled_at=raw.crawled_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def to_yaml_dict(self) -> dict[str, Any]:
        """Serialise to a dict whose structure matches the route-hacker YAML schema."""
        d: dict[str, Any] = {
            "CVE": self.CVE,
            "CVEDescription": self.CVEDescription,
            "CWE": self.CWE,
            "CWEDescription": self.CWEDescription,
            "severity": self.severity,
        }
        if self.cvss_score is not None:
            d["cvss_score"] = self.cvss_score
        if self.cvss_vector:
            d["cvss_vector"] = self.cvss_vector
        if self.published_date:
            d["published_date"] = self.published_date
        if self.modified_date:
            d["modified_date"] = self.modified_date
        if self.affected_software:
            d["affected_software"] = self.affected_software

        # patch fields
        d["patch_url"] = self.patch_url
        if self.patch_urls:
            d["patch_urls"] = self.patch_urls
        d["vul_version"] = self.vul_version

        # patched methods – semantic k-v (not tuple eval strings)
        if self.patch_method_before:
            d["patch_method_before"] = [m.model_dump() for m in self.patch_method_before]
        if self.patch_method_after:
            d["patch_method_after"] = [m.model_dump() for m in self.patch_method_after]

        # calltrace
        calltrace = self.CallTrace
        if calltrace is not None:
            d["CallTrace"] = {
                "before_traces": [
                    [f.model_dump() for f in trace] for trace in calltrace.before_traces
                ],
                "after_traces": [
                    [f.model_dump() for f in trace] for trace in calltrace.after_traces
                ],
            }
        else:
            d["CallTrace"] = {"before_traces": [], "after_traces": []}

        d["source"] = self.source
        d["sink"] = self.sink
        d["reason"] = self.reason

        if self.references:
            d["references"] = self.references
        if self.detail_url:
            d["detail_url"] = self.detail_url
        if self.crawled_at:
            d["crawled_at"] = self.crawled_at

        return d
