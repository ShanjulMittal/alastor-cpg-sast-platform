"""
Recursive file walker and source file discovery with SHA256 hashing.
Supports multi-language discovery for Python, JavaScript, and TypeScript.
"""
import os
import hashlib
from typing import List
from pydantic import BaseModel


class ScannedFile(BaseModel):
    filepath: str           # Relative path from project root (forward slashes)
    full_path: str          # Absolute filesystem path
    sha256: str             # Content SHA256
    language: str           # 'python', 'javascript', 'typescript', 'tsx'
    content_bytes: bytes


IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", 
    ".next", "dist", "build", ".pytest_cache", ".idea", ".vscode",
    ".mypy_cache", ".tox", "coverage", ".turbo", "scratch", "uploaded_scans"
}

CODE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx"
}


def scan_directory(root_dir: str) -> List[ScannedFile]:
    """
    Recursively scans the root_dir for supported source files (.py, .js, .jsx, .ts, .tsx).
    Also supports scanning a single file directly when root_dir is a file path.
    Returns deterministic sorted list of ScannedFile objects.
    """
    scanned_files: List[ScannedFile] = []
    abs_root = os.path.abspath(root_dir)

    if os.path.isfile(abs_root):
        filename = os.path.basename(abs_root)
        if filename.startswith("._") or filename.lower() in {".ds_store", "thumbs.db", "desktop.ini"}:
            return scanned_files
        ext = os.path.splitext(filename)[1].lower()
        language = CODE_EXTENSIONS.get(ext)
        if language:
            try:
                with open(abs_root, "rb") as f:
                    content = f.read()
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
            except Exception:
                pass
        return scanned_files

    is_synthetic_target = os.path.basename(abs_root).lower() == "synthetic_test_target"

    for current_dir, dirnames, filenames in os.walk(abs_root):
        # In-place filter to avoid traversing ignored directories (and exclude synthetic_test_target when auditing parent platform)
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORE_DIRS
            and not d.startswith(".")
            and (is_synthetic_target or d != "synthetic_test_target")
        ]

        for filename in filenames:
            if filename.startswith("._") or filename.lower() in {".ds_store", "thumbs.db", "desktop.ini"}:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext not in CODE_EXTENSIONS:
                continue

            lower_name = filename.lower()
            if (
                lower_name.endswith(".min.js")
                or lower_name.endswith(".bundle.js")
                or lower_name.endswith(".pack.js")
                or lower_name.endswith(".min.mjs")
            ):
                continue

            language = CODE_EXTENSIONS[ext]
            full_path = os.path.join(current_dir, filename)

            try:
                if os.path.getsize(full_path) > 1_000_000:
                    continue
            except OSError:
                continue

            rel_path = os.path.relpath(full_path, abs_root).replace("\\", "/")

            try:
                with open(full_path, "rb") as f:
                    content = f.read()
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
            except Exception:
                # Log and skip unreadable files
                continue

    # Deterministic ordering by relative filepath
    scanned_files.sort(key=lambda sf: sf.filepath)
    return scanned_files
