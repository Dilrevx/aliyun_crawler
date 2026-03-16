"""Aliyun AVD (avd.aliyun.com) vulnerability database crawler.

Crawls CVE entries from Aliyun's National Vulnerability Database mirror,
filters them through a chainable callback pipeline, resolves patch commits
via GitHub APIs, and optionally drives an LLM to produce calltrace fields
matching the route-hacker YAML schema.
"""

from aliyun_crawler.config import CrawlConfig, CrawlerSettings
from aliyun_crawler.crawler import AVDCrawler
from aliyun_crawler.filter import FilterPipeline
from aliyun_crawler.models import AVDCveEntry, CallTraceData, RawAVDEntry
from aliyun_crawler.storage import CrawlStorage

__all__ = [
    "CrawlConfig",
    "CrawlerSettings",
    "AVDCveEntry",
    "CallTraceData",
    "RawAVDEntry",
    "AVDCrawler",
    "FilterPipeline",
    "CrawlStorage",
]
