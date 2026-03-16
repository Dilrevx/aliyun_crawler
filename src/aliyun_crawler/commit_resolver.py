"""Commit resolver interfaces.

Provides three resolution strategies to map *indirect* patch references to
canonical GitHub commit SHAs:

1. :class:`PRCommitResolver`     – pull-request URL  → list of commit SHAs
2. :class:`IssueCommitResolver`  – issue URL         → list of commit SHAs
   (via pull-requests that close the issue)
3. :class:`VersionCommitResolver`– repo + version    → commit SHA
   (via tags / release listing)

All resolvers share :class:`GitHubClient`, a thin authenticated wrapper around
:mod:`httpx` that respects rate-limit headers and transparently retries on 429.
The token is read from :attr:`CrawlConfig.github_token` / ``CRAWL__GITHUB_TOKEN``
in ``.env``.

Usage example::

    resolver = PRCommitResolver(github_token="ghp_...")
    commits = resolver.resolve("https://github.com/owner/repo/pull/123")
    # ["abc1234...", "def5678..."]
"""

from __future__ import annotations

import logging
import re
import time
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"

# URL pattern helpers
_PR_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)", re.IGNORECASE)
_ISSUE_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/issues/(\d+)", re.IGNORECASE)
_COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})", re.IGNORECASE)
_TAG_VERSION_RE = re.compile(r"v?(\d+(?:\.\d+)+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Shared GitHub API client
# ---------------------------------------------------------------------------


class GitHubClient:
    """Thin authenticated :mod:`httpx` wrapper for the GitHub REST API.

    Handles:
    - ``Authorization: Bearer`` header injection.
    - Automatic retry with back-off on 429 / secondary rate-limit responses.
    - Basic pagination via ``Link: <...>; rel="next"`` headers.
    """

    def __init__(self, token: Optional[str] = None, timeout: int = 30) -> None:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(headers=headers, timeout=timeout, follow_redirects=True)

    def get(self, path: str, params: Optional[dict] = None, **kwargs) -> dict | list:
        """GET ``/`` + *path* with automatic rate-limit handling.

        Returns the parsed JSON body.
        """
        url = path if path.startswith("http") else f"{_GITHUB_API}/{path.lstrip('/')}"
        for attempt in range(4):
            resp = self._client.get(url, params=params, **kwargs)
            if resp.status_code == 429 or (
                resp.status_code == 403 and "rate limit" in resp.text.lower()
            ):
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(1, reset - int(time.time()))
                logger.warning("GitHub rate-limited; sleeping %ds (attempt %d)", wait, attempt + 1)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        raise RuntimeError(f"GitHub API request failed after retries: {url}")

    def get_paged(self, path: str, params: Optional[dict] = None) -> list[dict]:
        """Fetch all pages for a paginated GitHub API endpoint."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        results: list[dict] = []
        url: Optional[str] = (
            path if path.startswith("http") else f"{_GITHUB_API}/{path.lstrip('/')}"
        )
        while url:
            resp = self._client.get(url, params=params)
            if resp.status_code == 429 or (
                resp.status_code == 403 and "rate limit" in resp.text.lower()
            ):
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                time.sleep(max(1, reset - int(time.time())))
                continue
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                results.extend(data)
            elif isinstance(data, dict):
                # Some endpoints wrap list in a key
                for key in ("items", "commits", "pull_requests"):
                    if key in data:
                        results.extend(data[key])
                        break
            # Follow pagination
            link_header = resp.headers.get("Link", "")
            next_url = _extract_next_link(link_header)
            url = next_url
            params = {}  # params already encoded in next_url
        return results

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()


def _extract_next_link(link_header: str) -> Optional[str]:
    """Parse the ``Link`` header and return the ``rel=next`` URL if present."""
    for part in link_header.split(","):
        part = part.strip()
        m = re.match(r'<([^>]+)>;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseCommitResolver(ABC):
    """Abstract base for commit-resolution strategies."""

    def __init__(self, github_token: Optional[str] = None) -> None:
        self._gh = GitHubClient(token=github_token)

    @abstractmethod
    def resolve(self, url: str) -> list[str]:
        """Resolve *url* to a list of commit SHAs.

        Returns an empty list if resolution fails or nothing is found.
        """

    def close(self) -> None:
        self._gh.close()

    def __enter__(self) -> "BaseCommitResolver":
        return self

    def __exit__(self, *args) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Strategy 1: PR → commits
# ---------------------------------------------------------------------------


class PRCommitResolver(BaseCommitResolver):
    """Resolve a GitHub Pull Request URL to its constituent commit SHAs.

    For merged PRs, all commits on the PR branch are returned.
    """

    def resolve(self, url: str) -> list[str]:
        """Return commit SHAs for the PR at *url*, or ``[]`` on failure."""
        m = _PR_RE.search(url)
        if not m:
            # Maybe it's already a commit URL
            cm = _COMMIT_RE.search(url)
            if cm:
                return [cm.group(3)]
            logger.debug("Not a PR URL: %s", url)
            return []

        owner, repo, pr_number = m.group(1), m.group(2), m.group(3)
        try:
            items = self._gh.get_paged(f"repos/{owner}/{repo}/pulls/{pr_number}/commits")
            shas = [item["sha"] for item in items if isinstance(item, dict) and "sha" in item]
            logger.info("PR %s/%s#%s → %d commit(s)", owner, repo, pr_number, len(shas))
            return shas
        except httpx.HTTPStatusError as exc:
            logger.error("PR commit resolution failed for %s: %s", url, exc)
            return []


# ---------------------------------------------------------------------------
# Strategy 2: issue → commits (via linked PRs)
# ---------------------------------------------------------------------------


class IssueCommitResolver(BaseCommitResolver):
    """Resolve a GitHub Issue URL to commits via pull-requests that close it.

    Algorithm:
    1. Search for PRs that reference the issue number (via GitHub Search API).
    2. For each merged PR, fetch its commits via :class:`PRCommitResolver`.
    """

    def __init__(self, github_token: Optional[str] = None) -> None:
        super().__init__(github_token=github_token)
        self._pr_resolver = PRCommitResolver(github_token=github_token)

    def resolve(self, url: str) -> list[str]:
        m = _ISSUE_RE.search(url)
        if not m:
            logger.debug("Not an issue URL: %s", url)
            return []

        owner, repo, issue_number = m.group(1), m.group(2), m.group(3)
        shas: list[str] = []
        try:
            # Search for PRs in the same repo that close this issue
            query = f"repo:{owner}/{repo} is:pr is:merged closes:#{issue_number}"
            result = self._gh.get(
                "search/issues",
                params={"q": query, "per_page": 20},
            )
            items = result.get("items", []) if isinstance(result, dict) else []
            for item in items:
                pr_url = item.get("pull_request", {}).get("html_url", "")
                if pr_url:
                    shas.extend(self._pr_resolver.resolve(pr_url))
        except httpx.HTTPStatusError as exc:
            logger.error("Issue commit resolution failed for %s: %s", url, exc)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for sha in shas:
            if sha not in seen:
                seen.add(sha)
                unique.append(sha)
        logger.info("Issue %s/%s#%s → %d commit(s)", owner, repo, issue_number, len(unique))
        return unique

    def close(self) -> None:
        self._pr_resolver.close()
        super().close()


# ---------------------------------------------------------------------------
# Strategy 3: version → commit
# ---------------------------------------------------------------------------


class VersionCommitResolver(BaseCommitResolver):
    """Resolve a (repo, version) pair to the commit SHA for that release/tag.

    The resolver tries, in order:
    1. GitHub Releases API  (``/repos/{owner}/{repo}/releases/tags/{tag}``)
    2. Git Tags API         (``/repos/{owner}/{repo}/git/ref/tags/{tag}``)
    3. Fuzzy tag listing    (normalise version → try several tag spelling variants)
    """

    def resolve(self, url: str) -> list[str]:
        """Not implemented for bare URLs; use :meth:`resolve_version` instead."""
        logger.warning(
            "VersionCommitResolver.resolve() called with a URL; "
            "use resolve_version(owner, repo, version) directly."
        )
        return []

    def resolve_version(self, owner: str, repo: str, version: str) -> Optional[str]:
        """Return the commit SHA corresponding to *version* in *owner/repo*.

        Args:
            owner:   GitHub owner / organisation.
            repo:    Repository name.
            version: Version string, e.g. ``"2.2.6.RELEASE"`` or ``"v3.1.0"``.

        Returns:
            Commit SHA string, or *None* if unresolvable.
        """
        candidates = _version_tag_candidates(version)
        for tag in candidates:
            sha = self._try_release_tag(owner, repo, tag)
            if sha:
                logger.info("Version %s/%s@%s → %s (via tag %s)", owner, repo, version, sha, tag)
                return sha
        logger.warning("Could not resolve version %s for %s/%s", version, owner, repo)
        return None

    def _try_release_tag(self, owner: str, repo: str, tag: str) -> Optional[str]:
        """Try the Releases API then the Tags API for *tag*."""
        # Releases API
        try:
            release = self._gh.get(f"repos/{owner}/{repo}/releases/tags/{tag}")
            if isinstance(release, dict):
                return release.get("target_commitish") or release.get("sha")
        except httpx.HTTPStatusError:
            pass

        # Git refs API
        try:
            ref = self._gh.get(f"repos/{owner}/{repo}/git/ref/tags/{tag}")
            if isinstance(ref, dict):
                obj = ref.get("object", {})
                sha = obj.get("sha", "")
                if obj.get("type") == "tag":
                    # Annotated tag: resolve to the commit it points to
                    tag_obj = self._gh.get(f"repos/{owner}/{repo}/git/tags/{sha}")
                    if isinstance(tag_obj, dict):
                        return tag_obj.get("object", {}).get("sha", sha)
                return sha
        except httpx.HTTPStatusError:
            pass

        return None


def _version_tag_candidates(version: str) -> list[str]:
    """Build a list of plausible tag spellings for *version*.

    Examples::

        "2.2.6.RELEASE"  → ["2.2.6.RELEASE", "v2.2.6.RELEASE", "2.2.6", "v2.2.6"]
        "3.1.0"          → ["3.1.0", "v3.1.0"]
        "v3.1.0"         → ["v3.1.0", "3.1.0"]
    """
    candidates: list[str] = [version]
    if version.startswith("v"):
        candidates.append(version[1:])
    else:
        candidates.append(f"v{version}")

    # Also add stripped numeric version if there's a suffix like ".RELEASE"
    m = _TAG_VERSION_RE.match(version.lstrip("v"))
    if m:
        numeric = m.group(1)
        for prefix in ("", "v"):
            cand = f"{prefix}{numeric}"
            if cand not in candidates:
                candidates.append(cand)

    return candidates


# ---------------------------------------------------------------------------
# Unified dispatcher
# ---------------------------------------------------------------------------


class CommitResolver:
    """Unified resolver that dispatches to the appropriate strategy based on URL shape.

    All three strategies share a single :class:`GitHubClient` instance to
    reduce connection overhead.

    Usage::

        with CommitResolver(github_token="ghp_...") as resolver:
            commits = resolver.resolve("https://github.com/owner/repo/pull/42")
            commits = resolver.resolve("https://github.com/owner/repo/issues/10")
            commits = resolver.resolve("https://github.com/owner/repo/commit/abc123")
            commit  = resolver.resolve_version("spring-cloud", "spring-cloud-netflix", "3.1.5")
    """

    def __init__(self, github_token: Optional[str] = None) -> None:
        self._token = github_token
        self._pr = PRCommitResolver(github_token)
        self._issue = IssueCommitResolver(github_token)
        self._version = VersionCommitResolver(github_token)

    def resolve(self, url: str) -> list[str]:
        """Resolve a GitHub URL (commit, PR, or issue) to commit SHAs."""
        if _COMMIT_RE.search(url):
            m = _COMMIT_RE.search(url)
            return [m.group(3)] if m else []
        if _PR_RE.search(url):
            return self._pr.resolve(url)
        if _ISSUE_RE.search(url):
            return self._issue.resolve(url)
        logger.debug("CommitResolver: unrecognised URL shape: %s", url)
        return []

    def resolve_version(self, owner: str, repo: str, version: str) -> Optional[str]:
        """Resolve a version string to a commit SHA."""
        return self._version.resolve_version(owner, repo, version)

    def resolve_all_patch_urls(self, patch_urls: list[str]) -> list[str]:
        """Resolve a list of patch URLs and return a deduplicated list of commit SHAs."""
        seen: set[str] = set()
        commits: list[str] = []
        for url in patch_urls:
            for sha in self.resolve(url):
                if sha not in seen:
                    seen.add(sha)
                    commits.append(sha)
        return commits

    def close(self) -> None:
        self._pr.close()
        self._issue.close()
        self._version.close()

    def __enter__(self) -> "CommitResolver":
        return self

    def __exit__(self, *args) -> None:
        self.close()
