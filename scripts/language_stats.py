#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import httpx
import yaml

_REPO_PATTERNS = (
    re.compile(
        r"https?://github\.com/([^/]+)/([^/#?]+)/(?:commit|pull|issues?)/",
        re.IGNORECASE,
    ),
    re.compile(r"https?://github\.com/([^/]+)/([^/#?]+)$", re.IGNORECASE),
)

_EXT_TO_LANGUAGE = {
    ".java": "Java",
    ".php": "PHP",
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".go": "Go",
    ".rb": "Ruby",
    ".cs": "C#",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".c": "C",
    ".h": "C/C++ Header",
    ".hpp": "C/C++ Header",
    ".rs": "Rust",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".scala": "Scala",
    ".lua": "Lua",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".sh": "Shell",
}

_VULN_TYPE_PATTERNS: dict[str, tuple[str, ...]] = {
    "Access Control/Auth Bypass": (
        r"broken access control",
        r"improper access control",
        r"improper authorization",
        r"missing authorization",
        r"auth(?:entication|orization)? bypass",
        r"\bidor\b",
        r"insecure direct object reference",
        r"越权",
        r"未授权",
        r"权限绕过",
    ),
    "XSS": (
        r"\bxss\b",
        r"cross[ -]?site scripting",
        r"cross[ -]?site",
        r"跨站",
        r"脚本注入",
    ),
    "SQL Injection": (
        r"\bsqli\b",
        r"sql injection",
        r"数据库注入",
    ),
    "Command Injection": (
        r"command injection",
        r"os command",
        r"命令注入",
    ),
    "Path Traversal/LFI": (
        r"path traversal",
        r"directory traversal",
        r"local file inclusion",
        r"\blfi\b",
        r"路径遍历",
        r"任意文件读取",
        r"任意文件写入",
    ),
    "SSRF": (
        r"\bssrf\b",
        r"server[- ]side request forgery",
        r"服务端请求伪造",
    ),
    "RCE": (
        r"\brce\b",
        r"remote code execution",
        r"远程代码执行",
    ),
    "Deserialization": (
        r"deseriali[sz]ation",
        r"反序列化",
    ),
    "XML/XXE": (
        r"\bxxe\b",
        r"xml external entity",
        r"xml 实体",
        r"xml 解析",
    ),
    "CSRF": (
        r"\bcsrf\b",
        r"cross[- ]site request forgery",
        r"跨站请求伪造",
    ),
    "SSTI/Template Injection": (
        r"ssti",
        r"server[- ]side template injection",
        r"template injection",
        r"模板注入",
    ),
    "File Upload": (
        r"unrestricted file upload",
        r"arbitrary file upload",
        r"文件上传",
        r"上传",
    ),
    "Open Redirect": (
        r"open redirect",
        r"url redirect",
        r"重定向",
    ),
    "Memory Corruption/BOF": (
        r"buffer overflow",
        r"heap overflow",
        r"stack overflow",
        r"use[- ]after[- ]free",
        r"out[- ]of[- ]bounds",
        r"double free",
        r"内存破坏",
        r"越界",
    ),
    "DoS/Crash": (
        r"denial of service",
        r"\bdos\b",
        r"panic",
        r"crash",
        r"拒绝服务",
    ),
}

_COMPILED_VULN_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    name: [re.compile(item, re.IGNORECASE) for item in patterns]
    for name, patterns in _VULN_TYPE_PATTERNS.items()
}


def _extract_repo(url: str) -> str | None:
    text = (url or "").strip()
    if not text:
        return None
    for pattern in _REPO_PATTERNS:
        m = pattern.search(text)
        if m:
            owner = m.group(1)
            repo = m.group(2).rstrip(".git")
            return f"{owner}/{repo}"
    return None


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data
    return {}


def _iter_yaml_paths(yaml_dir: Path):
    yield from sorted(yaml_dir.glob("CVE-*.yaml"))


def _collect_cve_context(
    yaml_dir: Path,
) -> tuple[dict[str, set[str]], dict[str, str], int, int]:
    cve_to_repos: dict[str, set[str]] = defaultdict(set)
    cve_to_text: dict[str, str] = {}
    parse_errors = 0
    total_files = 0
    for path in _iter_yaml_paths(yaml_dir):
        total_files += 1
        cve = path.stem
        try:
            doc = _load_yaml(path)
        except Exception:
            parse_errors += 1
            continue

        desc = str(doc.get("CVEDescription") or "")
        reason = str(doc.get("reason") or "")
        source = " ".join(str(item) for item in (doc.get("source") or []))
        sink = " ".join(str(item) for item in (doc.get("sink") or []))
        cve_to_text[cve] = "\n".join([desc, reason, source, sink]).strip()

        urls: list[str] = []
        patch_url = doc.get("patch_url")
        if isinstance(patch_url, str) and patch_url.strip():
            urls.append(patch_url)

        patch_urls = doc.get("patch_urls")
        if isinstance(patch_urls, list):
            for item in patch_urls:
                if isinstance(item, str) and item.strip():
                    urls.append(item)

        refs = doc.get("references")
        if isinstance(refs, list):
            for item in refs:
                if isinstance(item, str) and "github.com" in item:
                    urls.append(item)

        for url in urls:
            repo = _extract_repo(url)
            if repo:
                cve_to_repos[cve].add(repo)

    return cve_to_repos, cve_to_text, parse_errors, total_files


def _classify_vulnerability_types(text: str) -> set[str]:
    lowered = (text or "").strip().lower()
    if not lowered:
        return {"Other/Unclassified"}

    matched: set[str] = set()
    for vuln_type, patterns in _COMPILED_VULN_PATTERNS.items():
        if any(pattern.search(lowered) for pattern in patterns):
            matched.add(vuln_type)

    if not matched:
        matched.add("Other/Unclassified")
    return matched


def _load_cache(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def _save_cache(path: Path, cache: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _github_primary_language(repo: str, token: str | None, timeout: int) -> str | None:
    owner, name = repo.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{name}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                lang = data.get("language")
                if isinstance(lang, str) and lang.strip():
                    return lang.strip()
                return "Unknown"
            return None
    except httpx.HTTPError:
        return None


def _local_primary_language(repo: str, repos_dir: Path, max_files: int) -> str | None:
    owner, name = repo.split("/", 1)
    local = repos_dir / f"{owner}__{name}"
    if not local.exists() or not local.is_dir():
        return None

    counter: Counter[str] = Counter()
    seen = 0
    for path in local.rglob("*"):
        if not path.is_file():
            continue
        if "/.git/" in str(path).replace("\\", "/"):
            continue
        ext = path.suffix.lower()
        lang = _EXT_TO_LANGUAGE.get(ext)
        if lang:
            counter[lang] += 1
            seen += 1
            if seen >= max_files:
                break

    if not counter:
        return "Unknown"
    return counter.most_common(1)[0][0]


def main() -> None:
    parser = argparse.ArgumentParser(description="统计 CVE 对应仓库语言分布")
    parser.add_argument("--data-dir", default="./output/aliyun_cve", help="数据根目录")
    parser.add_argument("--yaml-subdir", default="yaml", help="输入 YAML 子目录")
    parser.add_argument(
        "--repos-subdir",
        default="repos",
        help="本地仓库缓存子目录（用于离线语言推断）",
    )
    parser.add_argument(
        "--cache-file",
        default="./output/aliyun_cve/.cache/repo_languages.json",
        help="仓库语言缓存文件",
    )
    parser.add_argument("--top", type=int, default=20, help="输出前 N 个语言")
    parser.add_argument(
        "--top-types",
        type=int,
        default=12,
        help="二维分布中输出前 N 个漏洞类型列",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "github", "local"],
        default="auto",
        help="语言解析模式：auto(优先 github, 失败回退 local)",
    )
    parser.add_argument("--timeout", type=int, default=12, help="GitHub API 超时秒数")
    parser.add_argument(
        "--max-local-files",
        type=int,
        default=20000,
        help="本地推断时最多扫描文件数",
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    yaml_dir = data_dir / args.yaml_subdir
    repos_dir = data_dir / args.repos_subdir
    cache_path = Path(args.cache_file)

    if not yaml_dir.exists():
        raise SystemExit(f"输入目录不存在: {yaml_dir}")

    cve_to_repos, cve_to_text, parse_errors, total_cves = _collect_cve_context(yaml_dir)
    cves_with_repo = sum(1 for repos in cve_to_repos.values() if repos)

    all_repos = sorted({repo for repos in cve_to_repos.values() for repo in repos})
    cache = _load_cache(cache_path)

    token = os.getenv("GITHUB_TOKEN")
    resolved = 0
    failed = 0

    for repo in all_repos:
        cached = cache.get(repo)
        if cached:
            continue

        lang: str | None = None
        if args.mode in ("auto", "github"):
            lang = _github_primary_language(repo, token=token, timeout=args.timeout)
        if lang is None and args.mode in ("auto", "local"):
            lang = _local_primary_language(
                repo, repos_dir=repos_dir, max_files=args.max_local_files
            )

        if lang is None:
            lang = "Unknown"
            failed += 1
        else:
            resolved += 1

        cache[repo] = lang

    _save_cache(cache_path, cache)

    # Per-CVE language count: one vote per CVE per repo language (multi-repo CVE can contribute multiple votes)
    language_counter: Counter[str] = Counter()
    cve_to_languages: dict[str, set[str]] = {}
    for cve, repos in cve_to_repos.items():
        langs = {cache.get(repo, "Unknown") for repo in repos}
        if not langs:
            langs = {"Unknown"}
        cve_to_languages[cve] = langs
        for lang in langs:
            language_counter[lang] += 1

    # Vulnerability types and language x vuln-type matrix (count by CVE)
    type_counter: Counter[str] = Counter()
    matrix: dict[str, Counter[str]] = defaultdict(Counter)
    for cve, text in cve_to_text.items():
        types = _classify_vulnerability_types(text)
        langs = cve_to_languages.get(cve, {"Unknown"})
        for vuln_type in types:
            type_counter[vuln_type] += 1
        for lang in langs:
            for vuln_type in types:
                matrix[lang][vuln_type] += 1

    print(f"输入目录: {yaml_dir}")
    print(f"总 CVE 文件: {total_cves}")
    print(f"含 GitHub 仓库的 CVE: {cves_with_repo}")
    print(f"唯一仓库数: {len(all_repos)}")
    print(f"YAML 解析失败: {parse_errors}")
    print(f"本次新增解析: {resolved}")
    print(f"本次解析失败(记为 Unknown): {failed}")
    print(f"缓存文件: {cache_path}")

    total_votes = sum(language_counter.values())
    if total_votes == 0:
        print("\n无可统计语言（可能没有可解析的 GitHub 仓库 URL）")
        return

    print("\n语言分布（按 CVE 计数）:")
    for lang, count in language_counter.most_common(max(1, args.top)):
        pct = count / total_votes
        print(f"  {lang:14s} {count:6d}  {pct:.2%}")

    total_type_votes = sum(type_counter.values())
    if total_type_votes:
        print("\n漏洞类型分布（文本匹配，按 CVE 计数）:")
        for vuln_type, count in type_counter.most_common(max(1, args.top_types)):
            pct = count / total_type_votes
            print(f"  {vuln_type:24s} {count:6d}  {pct:.2%}")

    top_languages = [lang for lang, _ in language_counter.most_common(max(1, args.top))]
    top_types = [t for t, _ in type_counter.most_common(max(1, args.top_types))]
    if top_languages and top_types:
        print("\n语言-漏洞类型二维分布（按 CVE 计数）:")
        header = ["Language"] + top_types
        rows: list[list[str]] = []
        for lang in top_languages:
            row = [lang] + [
                str(matrix[lang].get(vuln_type, 0)) for vuln_type in top_types
            ]
            rows.append(row)

        widths = [len(col) for col in header]
        for row in rows:
            for idx, cell in enumerate(row):
                if len(cell) > widths[idx]:
                    widths[idx] = len(cell)

        def _fmt(line: list[str]) -> str:
            return " | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(line))

        print(_fmt(header))
        print("-+-".join("-" * width for width in widths))
        for row in rows:
            print(_fmt(row))


if __name__ == "__main__":
    main()
