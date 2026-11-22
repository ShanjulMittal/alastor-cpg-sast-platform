"""
Hostile-Repo-Safe Polyglot File Walker & Source Discovery for ALASTOR v5.0.

Provides:
- 18-language / 55+ extension discovery via compiler.language_registry
- Strict symlink confinement (os.path.realpath + os.path.commonpath, followlinks=False)
- Pure-Python nested .gitignore evaluation (never invokes target git hooks or loads .env)
- Contextual ecosystem build-output directory exclusions (Rust/Maven/Gradle/SBT/DotNet/CocoaPods/Foundry/Hardhat)
- Generated stub filtering and optional test exclusion with structured ScanScopeTelemetry
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel

from compiler.language_registry import (
    EXTENSION_TO_LANGUAGE,
    resolve_language_for_filename,
)
from models import ScanScopeTelemetry


class ScannedFile(BaseModel):
    filepath: str           # Relative path from project root (forward slashes)
    full_path: str          # Absolute filesystem path
    sha256: str             # Content SHA256
    language: str           # Canonical 18-family key (e.g. 'python', 'go', 'web_template')
    content_bytes: bytes


IGNORE_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".next",
    "dist",
    "build",
    ".pytest_cache",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".tox",
    "coverage",
    ".turbo",
    ".gradle",
    ".dart_tool",
    "vendor",
    "third_party",
    "bower_components",
    "scratch",
    "uploaded_scans",
}

# Exported & aligned with declarative 18-language registry (55+ extensions)
CODE_EXTENSIONS: Dict[str, str] = dict(EXTENSION_TO_LANGUAGE)

_OS_JUNK_FILES: Set[str] = {".ds_store", "thumbs.db", "desktop.ini"}

_GENERATED_SUFFIXES: Tuple[str, ...] = (
    ".pb.go",
    "_pb2.py",
    "_pb2_grpc.py",
    ".g.cs",
    ".designer.cs",
    ".min.js",
    ".bundle.js",
    ".pack.js",
    ".min.mjs",
)

_TEST_DIR_NAMES: Set[str] = {"tests", "test", "__tests__", "spec", "specs"}

_TARGET_MANIFESTS: Set[str] = {
    "pom.xml",
    "cargo.toml",
    "build.gradle",
    "build.gradle.kts",
    "build.sbt",
}

_HARDHAT_MANIFESTS: Set[str] = {
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
}

_MAX_FILE_SIZE_BYTES = 1_000_000


@dataclass(frozen=True)
class _GitignoreRule:
    base_rel_dir: str   # "" for root, or "sub/dir" (forward slashes)
    pattern: str        # normalized pattern without leading ! or leading/trailing /
    negated: bool
    dir_only: bool
    anchored: bool      # True if pattern had leading / or internal /


def _is_link_or_junction(path: str) -> bool:
    """Detects POSIX/Windows symlinks as well as Windows NTFS directory junctions."""
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if callable(isjunction):
        try:
            return bool(isjunction(path))
        except OSError:
            return False
    return False


def _is_confined(real_root: str, candidate_path: str) -> bool:
    """Returns True iff realpath(candidate_path) stays strictly inside real_root."""
    try:
        real_target = os.path.realpath(candidate_path)
        return os.path.commonpath([real_root, real_target]) == real_root
    except ValueError:
        return False


def _parse_gitignore_file(gitignore_path: str, base_rel_dir: str) -> List[_GitignoreRule]:
    """Pure-Python .gitignore parser. Never executes git or reads external configs."""
    rules: List[_GitignoreRule] = []
    try:
        with open(gitignore_path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.read().splitlines()
    except OSError:
        return rules

    for raw in raw_lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:].strip()
            if not line:
                continue

        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")
            if not line:
                continue

        anchored = line.startswith("/")
        if anchored:
            line = line.lstrip("/")
            if not line:
                continue

        if "/" in line:
            anchored = True

        rules.append(
            _GitignoreRule(
                base_rel_dir=base_rel_dir,
                pattern=line,
                negated=negated,
                dir_only=dir_only,
                anchored=anchored,
            )
        )
    return rules


def _match_segments(path_parts: List[str], pat_parts: List[str]) -> bool:
    """Linear/memoized segment glob matcher supporting '**' without regex backtracking."""
    m = len(path_parts)
    n = len(pat_parts)
    dp = [False] * (n + 1)
    dp[0] = True
    for j in range(1, n + 1):
        if pat_parts[j - 1] == "**":
            dp[j] = dp[j - 1]

    for i in range(1, m + 1):
        next_dp = [False] * (n + 1)
        for j in range(1, n + 1):
            pat = pat_parts[j - 1]
            if pat == "**":
                next_dp[j] = next_dp[j - 1] or dp[j]
            elif fnmatch.fnmatchcase(path_parts[i - 1], pat):
                next_dp[j] = dp[j - 1]
        dp = next_dp
    return dp[n]


def _rule_matches(rule: _GitignoreRule, rel_path: str, is_dir: bool) -> bool:
    if rule.dir_only and not is_dir:
        return False

    if rule.base_rel_dir:
        prefix = rule.base_rel_dir + "/"
        if not rel_path.startswith(prefix):
            return False
        local_rel = rel_path[len(prefix):]
    else:
        local_rel = rel_path

    if not local_rel:
        return False

    if rule.anchored:
        if "**" in rule.pattern:
            return _match_segments(local_rel.split("/"), rule.pattern.split("/"))
        return fnmatch.fnmatchcase(local_rel, rule.pattern)

    basename = local_rel.rsplit("/", 1)[-1]
    if fnmatch.fnmatchcase(basename, rule.pattern):
        return True
    if fnmatch.fnmatchcase(local_rel, rule.pattern):
        return True
    return False


def _is_gitignored(
    rel_path: str,
    is_dir: bool,
    ancestor_dirs: List[str],
    rules_by_dir: Dict[str, List[_GitignoreRule]],
) -> bool:
    ignored = False
    for d in ancestor_dirs:
        for rule in rules_by_dir.get(d, ()):
            if _rule_matches(rule, rel_path, is_dir=is_dir):
                ignored = not rule.negated
    return ignored


def _contextual_build_dirs_for_manifests(filenames: List[str]) -> Set[str]:
    """
    Determines ecosystem build-output directory names (lowercased) that should be
    excluded in the current directory based on co-located build manifests.
    """
    lower_files = {f.lower() for f in filenames}
    excluded: Set[str] = set()

    if lower_files & _TARGET_MANIFESTS:
        excluded.add("target")

    if any(f.endswith((".csproj", ".fsproj", ".sln")) for f in lower_files):
        excluded.add("bin")
        excluded.add("obj")

    if "podfile" in lower_files:
        excluded.add("pods")

    if "foundry.toml" in lower_files:
        excluded.add("out")

    if lower_files & _HARDHAT_MANIFESTS:
        excluded.add("artifacts")
        excluded.add("cache")

    return excluded


def _is_generated_stub(filename: str) -> bool:
    lower_name = filename.lower()
    if any(lower_name.endswith(sfx) for sfx in _GENERATED_SUFFIXES):
        return True
    if ".generated." in lower_name:
        return True
    return False


def _is_test_file(rel_path: str, filename: str) -> bool:
    parts = [p.lower() for p in rel_path.split("/")[:-1]]
    if any(p in _TEST_DIR_NAMES for p in parts):
        return True
    lower = filename.lower()
    stem = os.path.splitext(lower)[0]
    if lower.startswith("test_") or stem.endswith("_test") or stem.endswith("_spec"):
        return True
    if ".test." in lower or ".spec." in lower:
        return True
    if filename.endswith(("Test.java", "Tests.java", "Test.kt", "Tests.kt", "Test.cs", "Tests.cs")):
        return True
    return False


def _ancestor_rel_dirs(rel_dir: str) -> List[str]:
    if not rel_dir or rel_dir == ".":
        return [""]
    parts = rel_dir.split("/")
    ancestors = [""]
    acc = ""
    for part in parts:
        acc = f"{acc}/{part}" if acc else part
        ancestors.append(acc)
    return ancestors


def scan_directory_with_telemetry(
    root_dir: str,
    exclude_tests: bool = False,
) -> Tuple[List[ScannedFile], ScanScopeTelemetry]:
    """
    Recursively scans root_dir across all 18 supported language families with
    hostile-repo protections and returns (scanned_files, ScanScopeTelemetry).
    """
    scanned_files: List[ScannedFile] = []
    telemetry = ScanScopeTelemetry()
    abs_root = os.path.abspath(root_dir)

    if os.path.isfile(abs_root):
        filename = os.path.basename(abs_root)
        if filename.startswith("._") or filename.lower() in _OS_JUNK_FILES:
            return scanned_files, telemetry
        if _is_generated_stub(filename):
            telemetry.generated_excluded += 1
            return scanned_files, telemetry
        language = resolve_language_for_filename(filename)
        if language:
            try:
                if os.path.getsize(abs_root) <= _MAX_FILE_SIZE_BYTES:
                    with open(abs_root, "rb") as fh:
                        content = fh.read()
                    file_hash = hashlib.sha256(content).hexdigest()
                    scanned_files.append(
                        ScannedFile(
                            filepath=filename.replace("\\", "/"),
                            full_path=abs_root,
                            sha256=file_hash,
                            language=language,
                            content_bytes=content,
                        )
                    )
                    telemetry.total_discovered = 1
                    telemetry.languages_breakdown[language] = 1
            except OSError:
                pass
        return scanned_files, telemetry

    real_root = os.path.realpath(abs_root)
    is_synthetic_target = os.path.basename(abs_root).lower() == "synthetic_test_target"
    rules_by_dir: Dict[str, List[_GitignoreRule]] = {}

    for current_dir, dirnames, filenames in os.walk(abs_root, followlinks=False):
        rel_dir_raw = os.path.relpath(current_dir, abs_root).replace("\\", "/")
        rel_dir = "" if rel_dir_raw == "." else rel_dir_raw

        # Load scoped .gitignore if present in current_dir (confined regular file only)
        if ".gitignore" in filenames:
            gi_path = os.path.join(current_dir, ".gitignore")
            if not _is_link_or_junction(gi_path) or _is_confined(real_root, gi_path):
                rules_by_dir[rel_dir] = _parse_gitignore_file(gi_path, rel_dir)

        ancestors = _ancestor_rel_dirs(rel_dir)
        contextual_build_dirs = _contextual_build_dirs_for_manifests(filenames)

        kept_dirs: List[str] = []
        for d in sorted(dirnames):
            full_subdir = os.path.join(current_dir, d)
            sub_rel = f"{rel_dir}/{d}" if rel_dir else d

            # 1. Hostile symlink / NTFS junction confinement check
            if _is_link_or_junction(full_subdir):
                if not _is_confined(real_root, full_subdir):
                    telemetry.symlinks_dropped += 1
                # Never recurse through symlinked/junctioned directories (followlinks=False)
                continue

            # 2. Preserve existing synthetic_test_target exclusion on parent platform audits
            if not is_synthetic_target and d == "synthetic_test_target":
                continue

            # 3. Contextual ecosystem build-output directory exclusion
            if d.lower() in contextual_build_dirs:
                telemetry.build_dirs_excluded += 1
                continue

            # 4. Standard VCS/tool caches and hidden directories
            if d in IGNORE_DIRS or d.startswith("."):
                continue

            # 5. Pure-Python nested .gitignore directory exclusion
            if _is_gitignored(sub_rel, is_dir=True, ancestor_dirs=ancestors, rules_by_dir=rules_by_dir):
                telemetry.gitignore_excluded += 1
                continue

            kept_dirs.append(d)

        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            if filename.startswith("._") or filename.lower() in _OS_JUNK_FILES:
                continue

            full_path = os.path.join(current_dir, filename)
            rel_path = f"{rel_dir}/{filename}" if rel_dir else filename

            # 1. Hostile symlink confinement check on files (before .gitignore skip so escaping links are counted)
            if _is_link_or_junction(full_path):
                if not _is_confined(real_root, full_path):
                    telemetry.symlinks_dropped += 1
                    continue

            if filename == ".gitignore":
                continue

            # 2. Pure-Python nested .gitignore file exclusion
            if _is_gitignored(rel_path, is_dir=False, ancestor_dirs=ancestors, rules_by_dir=rules_by_dir):
                telemetry.gitignore_excluded += 1
                continue

            # 3. Generated stub exclusion (checked before language parsing)
            if _is_generated_stub(filename):
                telemetry.generated_excluded += 1
                continue

            # 4. Resolve canonical 18-family language (compound suffixes first)
            language = resolve_language_for_filename(filename)
            if language is None:
                continue

            # 5. Optional test file exclusion (default False)
            if exclude_tests and _is_test_file(rel_path, filename):
                telemetry.tests_excluded += 1
                continue

            try:
                if os.path.getsize(full_path) > _MAX_FILE_SIZE_BYTES:
                    continue
                with open(full_path, "rb") as fh:
                    content = fh.read()
            except OSError:
                continue

            file_hash = hashlib.sha256(content).hexdigest()
            scanned_files.append(
                ScannedFile(
                    filepath=rel_path,
                    full_path=full_path,
                    sha256=file_hash,
                    language=language,
                    content_bytes=content,
                )
            )
            telemetry.total_discovered += 1
            telemetry.languages_breakdown[language] = telemetry.languages_breakdown.get(language, 0) + 1

    scanned_files.sort(key=lambda sf: sf.filepath)
    return scanned_files, telemetry


def scan_directory(root_dir: str) -> List[ScannedFile]:
    """
    Backward-compatible entry point preserving the exact ALASTOR v4.0 signature.
    Recursively scans root_dir across all 18 supported language families.
    """
    scanned_files, _ = scan_directory_with_telemetry(root_dir, exclude_tests=False)
    return scanned_files
