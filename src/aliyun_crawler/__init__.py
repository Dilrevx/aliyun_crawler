"""Aliyun AVD (avd.aliyun.com) vulnerability database crawler.

Crawls CVE entries from Aliyun's National Vulnerability Database mirror,
filters them through a chainable callback pipeline, resolves patch commits
via GitHub APIs, and optionally drives an LLM to produce calltrace fields
matching the route-hacker YAML schema.
"""

from .config import CrawlConfig, CrawlerSettings
from .crawler import AVDCrawler
from .filter import FilterPipeline
from .models import AVDCveEntry, CallTraceData, RawAVDEntry
from .rawdb import RawIngestService, build_raw_repository, create_app
from .storage import CrawlStorage
from .tracer import CalltraceExplorer, TokenStats

__all__ = [
    "CrawlConfig",
    "CrawlerSettings",
    "AVDCveEntry",
    "CallTraceData",
    "RawAVDEntry",
    "AVDCrawler",
    "FilterPipeline",
    "CrawlStorage",
    "CalltraceExplorer",
    "TokenStats",
    "RawIngestService",
    "build_raw_repository",
    "create_app",
]
