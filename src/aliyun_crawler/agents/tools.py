from __future__ import annotations

import dataclasses
import os
import re
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


@dataclasses.dataclass
class ToolRequest:
    name: str
    params: dict[str, object]


@dataclasses.dataclass
class ToolResult:
    ok: bool
    data: object | None = None
    error: str | None = None


class RepositoryTools:
    """Repository-scoped helper tools for calltrace analysis.

    This class intentionally keeps behavior deterministic and lightweight.
    It can be used by coordinator / explorer / evaluator style workflows.
    """

    _SAFE_COMMANDS = {"rg", "grep", "find", "ls", "git"}

    def __init__(
        self, clone_via_ssh: bool = False, git_proxy: Optional[str] = None
    ) -> None:
        self.clone_via_ssh = clone_via_ssh
        self.git_proxy = git_proxy

    def run_safe_command(
        self,
        command: list[str],
        cwd: Path,
        timeout_sec: int = 20,
    ) -> ToolResult:
        if not command:
            return ToolResult(ok=False, error="empty command")
        program = command[0]
        if program not in self._SAFE_COMMANDS:
            return ToolResult(ok=False, error=f"command not allowed: {program}")

        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
            return ToolResult(
                ok=completed.returncode == 0,
                data={
                    "returncode": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                },
            )
        except Exception as exc:
            return ToolResult(ok=False, error=str(exc))

    def _run_git(
        self,
        args: list[str],
        cwd: Path,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if self.git_proxy:
            env["HTTP_PROXY"] = self.git_proxy
            env["HTTPS_PROXY"] = self.git_proxy
        return subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=check,
            env=env if self.git_proxy else None,
        )

    @staticmethod
    def _to_ssh_url(https_url: str) -> str:
        m = re.match(r"https://github\.com/([^/]+/.+)", https_url)
        if m:
            return f"git@github.com:{m.group(1)}"
        return https_url

    def clone_or_update(self, repo_url: str, repos_dir: Path) -> Path:
        parsed = urlparse(repo_url)
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            raise ValueError(f"Cannot derive repo name from URL: {repo_url}")

        local_name = f"{parts[0]}__{parts[1]}"
        local_path = repos_dir / local_name
        effective_url = self._to_ssh_url(repo_url) if self.clone_via_ssh else repo_url

        if local_path.exists():
            self._run_git(["fetch", "--all", "--prune"], cwd=local_path, check=False)
        else:
            repos_dir.mkdir(parents=True, exist_ok=True)
            self._run_git(
                ["clone", "--filter=blob:none", effective_url, local_name],
                cwd=repos_dir,
            )
        return local_path

    def checkout(self, repo_path: Path, ref: str) -> None:
        self._run_git(["checkout", "--detach", ref], cwd=repo_path)

    def get_parent_commit(self, repo_path: Path, commit_sha: str) -> Optional[str]:
        result = self._run_git(
            ["rev-parse", f"{commit_sha}^"], cwd=repo_path, check=False
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def get_diff(self, repo_path: Path, commit_sha: str, unified: int = 10) -> str:
        result = self._run_git(
            ["diff", f"{commit_sha}^", commit_sha, f"--unified={unified}"],
            cwd=repo_path,
            check=False,
        )
        return result.stdout

    @staticmethod
    def parse_diff_files(diff: str) -> list[str]:
        files: list[str] = []
        for m in re.finditer(r"^\+\+\+ b/(.+)$", diff, re.MULTILINE):
            files.append(m.group(1))
        return files

    @staticmethod
    def read_repo_file(repo_path: Path, rel_path: str) -> str:
        full = repo_path / rel_path
        if not full.exists():
            return ""
        try:
            return full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    @staticmethod
    def get_file_structure(
        repo_path: Path, rel_dir: str = ".", max_depth: int = 3
    ) -> list[str]:
        base = (repo_path / rel_dir).resolve()
        if not base.exists() or not base.is_dir():
            return []

        out: list[str] = []
        base_parts = len(base.parts)
        for path in sorted(base.rglob("*")):
            depth = len(path.parts) - base_parts
            if depth > max_depth:
                continue
            rel = str(path.relative_to(repo_path))
            out.append(rel + ("/" if path.is_dir() else ""))
        return out

    def search_text(
        self, repo_path: Path, query: str, include_glob: str = "*"
    ) -> ToolResult:
        cmd = ["rg", "-n", query, "--glob", include_glob, "."]
        return self.run_safe_command(cmd, cwd=repo_path)

    def find_usages(
        self, repo_path: Path, symbol: str, include_glob: str = "*"
    ) -> ToolResult:
        escaped = re.escape(symbol)
        return self.search_text(repo_path, rf"\b{escaped}\b", include_glob=include_glob)

    @staticmethod
    def get_function_body(file_content: str, symbol: str, language: str = "") -> str:
        lines = file_content.splitlines()
        if not lines:
            return ""

        if language in {"py", "python"}:
            pattern = re.compile(rf"^\s*(def|class)\s+{re.escape(symbol)}\b")
            start = -1
            for idx, line in enumerate(lines):
                if pattern.search(line):
                    start = idx
                    break
            if start < 0:
                return ""
            indent = len(lines[start]) - len(lines[start].lstrip())
            end = len(lines)
            for idx in range(start + 1, len(lines)):
                stripped = lines[idx].strip()
                if not stripped:
                    continue
                curr_indent = len(lines[idx]) - len(lines[idx].lstrip())
                if curr_indent <= indent and not lines[idx].lstrip().startswith(
                    ("#", "@")
                ):
                    end = idx
                    break
            return "\n".join(lines[start:end])

        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        start = -1
        for idx, line in enumerate(lines):
            if pattern.search(line) and "(" in line:
                start = idx
                break
        if start < 0:
            return ""

        text = "\n".join(lines[start:])
        balance = 0
        end_offset = 0
        opened = False
        for pos, char in enumerate(text):
            if char == "{":
                balance += 1
                opened = True
            elif char == "}":
                balance -= 1
                if opened and balance == 0:
                    end_offset = pos + 1
                    break
        if end_offset > 0:
            return text[:end_offset]
        return "\n".join(lines[start : min(start + 120, len(lines))])


class SummaryTool:
    """Rule-based summary helper for large source content."""

    SIGNATURE_PATTERNS = (
        re.compile(r"^\s*(def|class)\s+[A-Za-z_][A-Za-z0-9_]*"),
        re.compile(r"^\s*(public|private|protected|static|async|func|function)\b"),
        re.compile(r"^\s*(interface|type)\b"),
    )

    def summarize_file(
        self, content: str, max_lines: int = 80, max_chars: int = 4000
    ) -> str:
        selected: list[str] = []
        for line in content.splitlines():
            if any(p.search(line) for p in self.SIGNATURE_PATTERNS):
                selected.append(line)
            if len(selected) >= max_lines:
                break
        if not selected:
            selected = content.splitlines()[: max_lines // 2]

        text = "\n".join(selected)
        return text[:max_chars]
