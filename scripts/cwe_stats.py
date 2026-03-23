#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

import yaml

LOGIC_CWES = {
    "CWE-284",
    "CWE-285",
    "CWE-862",
    "CWE-863",
    "CWE-639",
}


def _norm_cwe(value: object) -> str:
    if value is None:
        return "UNKNOWN"
    text = str(value).strip().upper()
    return text if text else "UNKNOWN"


def _iter_yaml_files(directory: Path):
    yield from sorted(directory.glob("CVE-*.yaml"))


def collect_cwe_counts(directory: Path) -> tuple[Counter[str], int]:
    counter: Counter[str] = Counter()
    total = 0
    for path in _iter_yaml_files(directory):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            counter["PARSE_ERROR"] += 1
            total += 1
            continue

        cwe = _norm_cwe(data.get("CWE"))
        counter[cwe] += 1
        total += 1
    return counter, total


def main() -> None:
    parser = argparse.ArgumentParser(description="统计 CVE YAML 中的 CWE 分布")
    parser.add_argument(
        "--data-dir",
        default="./output/aliyun_cve",
        help="数据根目录（默认: ./output/aliyun_cve）",
    )
    parser.add_argument(
        "--subdir",
        default="yaml",
        help="要统计的子目录（如 yaml / yaml_calltrace）",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=30,
        help="展示前 N 个 CWE（默认: 30）",
    )
    args = parser.parse_args()

    target_dir = Path(args.data_dir) / args.subdir
    if not target_dir.exists():
        raise SystemExit(f"目录不存在: {target_dir}")

    counts, total = collect_cwe_counts(target_dir)
    if total == 0:
        print(f"目录为空或无匹配文件: {target_dir}")
        return

    logic_total = sum(counts[cwe] for cwe in LOGIC_CWES)
    non_logic_total = total - logic_total

    print(f"目录: {target_dir}")
    print(f"总文件数: {total}")
    print(
        f"逻辑漏洞(CWE {sorted(LOGIC_CWES)}): {logic_total} ({logic_total / total:.2%})"
    )
    print(f"非逻辑/未知: {non_logic_total} ({non_logic_total / total:.2%})")

    print("\nTop CWE:")
    for cwe, count in counts.most_common(max(1, args.top)):
        print(f"  {cwe:12s} {count:6d}  {count / total:.2%}")

    non_logic_items = [
        (cwe, count) for cwe, count in counts.most_common() if cwe not in LOGIC_CWES
    ]
    if non_logic_items:
        print("\n非逻辑/未知 CWE 明细:")
        for cwe, count in non_logic_items:
            print(f"  {cwe:12s} {count:6d}  {count / total:.2%}")


if __name__ == "__main__":
    main()
