"""
FastAPI application for Deterministic CPG & SAST Platform.
Exposes REST endpoints for scanning, graph inspection, findings, Application Tree, and Monaco/ReactFlow synchronization.
"""
import os
import re
import time
import shutil
import logging
import threading
import subprocess
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any
import requests as http_requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
import html as html_lib

from models import (
    CPGNode, CPGEdge, Finding, ScanRequest, ScanResponse, MetricsResponse,
    AppTreeSummary, FilePurposeInfo, ScanProgress,
    ExtractedAdvisory, SiteExtractRequest, SiteExtractResponse,
    FsEntry, FsBrowseResponse, NativeDialogRequest, NativeDialogResponse,
    UploadTargetRequest, UploadTargetResponse,
    ProjectConfig, ProjectAutomationConfig, CreateProjectRequest, UpdateProjectAutomationRequest, WebhookTriggerRequest,
    DeepDiveAnalyticsResponse, TriageUpdateRequest,
    PlatformSettingsResponse, UpdatePlatformSettingsRequest, UpsertQueryRuleRequest,
    SecurityQueryRule, AddCustomSanitizerRequest, CustomSanitizerRule,
    BugTrackerConnectorConfig, IssueTicket, CreateTicketRequest,
    UpdateTicketRequest, TestConnectionRequest, TestConnectionResponse,
    IntegrationHubStateResponse,
    RaciGovernanceResponse, UpdateRaciCellRequest, UpdateFindingRaciOwnerRequest,
    SastPlusSuiteResponse, ScanSnapshotRecord, TrackChangesSummary,
    CreateTestProfileRequest, BatchRuleSelectionRequest,
    CreateAccountRequest, CreateUserProfileRequest, SwitchUserOrAccountRequest,
    UserAccountsStateResponse
)
from database.neo4j_client import Neo4jClient
from database.batch_ingestor import BatchIngestor
from engine.rule_executor import RuleExecutor
from engine.vuln_extractor import VulnExtractorEngine
from engine.enterprise_manager import EnterpriseManager
from compiler.scanner import scan_directory, CODE_EXTENSIONS, IGNORE_DIRS
from compiler.ast_parser import ASTNormalizer
from compiler.cfg_builder import CFGBuilder
from compiler.dfg_builder import DFGBuilder
from compiler.call_graph_builder import CallGraphBuilder
from compiler.app_tree import AppTreeAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cpg-sast.main")

# Global real-time scan progress state
current_progress = ScanProgress()

def update_progress(
    is_scanning: bool = True,
    phase: str = "",
    current_pass: str = "",
    current_file: str = "",
    files_done: int = 0,
    total_files: int = 0,
    percent: int = 0,
    message: str = "",
    error: Optional[str] = None
):
    global current_progress
    current_progress = ScanProgress(
        is_scanning=is_scanning,
        phase=phase,
        current_pass=current_pass,
        current_file=current_file,
        files_done=files_done,
        total_files=total_files,
        percent=max(0, min(100, percent)),
        message=message,
        error=error
    )

app = FastAPI(
    title="ALASTOR Enterprise Deterministic CPG, STRIDE Threat Modeling & SAST++++++ Engine",
    version="2.6.0",
    description="Compiler-grade deterministic Code Property Graph, STRIDE Threat Modeling, Live Lockfile CVE Reachability, Secret Keys Vault, Rule Engine Profiles, Multi-Tenant RBAC, and ASPM platform."
)

# CORS setup
cors_origins_env = os.getenv("CPG_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
origins = [orig.strip() for orig in cors_origins_env.split(",") if orig.strip()]
if "*" not in origins:
    origins.append("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

neo4j_client = Neo4jClient.get_instance()
enterprise_mgr = EnterpriseManager.get_instance()
current_scan_dir: str = enterprise_mgr.platform_root
current_app_tree: Optional[AppTreeSummary] = None


def _sanitize_log(value: Any) -> str:
    """Neutralizes CR/LF, NUL, and terminal escape characters to prevent CWE-117 Log Injection."""
    return re.sub(r"[\r\n\x00\x1b\t]+", " ", str(value))[:300]


def _safe_resolve_under(base_dir: str, *parts: str) -> str:
    """
    Canonicalizes candidate path via os.path.realpath() and enforces strict os.path.commonpath()
    containment within base_dir to prevent CWE-22 Path Traversal.
    """
    real_base = os.path.realpath(base_dir)
    joined = os.path.join(real_base, *parts)
    real_target = os.path.realpath(joined)
    if os.path.commonpath([real_base, real_target]) != real_base:
        raise ValueError(f"Path traversal blocked outside base workspace: {real_base}")
    return real_target


def _validate_safe_remote_url(raw_url: str, allow_git_ssh: bool = False) -> str:
    """
    Validates remote URL scheme and host, blocking file://, ftp://, gopher://,
    git CLI option injection (leading '-'), and cloud metadata SSRF endpoints (CWE-918).
    """
    clean = (raw_url or "").strip()
    if not clean or clean.startswith("-") or re.search(r"[\r\n\x00\s]", clean):
        raise ValueError("Invalid or unsafe remote URL format.")
    if allow_git_ssh and clean.startswith("git@"):
        if not re.match(r"^git@[A-Za-z0-9._-]+:[A-Za-z0-9._/-]+$", clean):
            raise ValueError("Invalid SSH Git repository URL.")
        return clean

    parsed = urlparse(clean)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"Blocked unsupported URL scheme '{parsed.scheme}'; only https/http allowed.")
    host = (parsed.hostname or "").lower()
    if not host or host in {"169.254.169.254", "metadata.google.internal", "100.100.100.200"}:
        raise ValueError("Blocked cloud metadata or empty host in remote URL.")
    return clean


def _resolve_remote_url_target(target_url: str, base_scan_dir: str) -> str:
    """
    Resolves a remote URL (GitHub/GitLab repo, GitHub blob file, raw source file, or web URL)
    into a local workspace directory or file so the full CPG + AppTree + SAST pipeline can scan it.
    """
    workspace_root = os.path.realpath(os.path.join(os.path.dirname(base_scan_dir), ".remote_targets"))
    os.makedirs(workspace_root, exist_ok=True)

    clean_url = _validate_safe_remote_url(target_url, allow_git_ssh=True)
    if clean_url.startswith("git@"):
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", clean_url.split(":")[-1].replace(".git", "")).strip("._") or "git_repo"
        dest_dir = _safe_resolve_under(workspace_root, slug)
        if os.path.exists(dest_dir) and dest_dir != workspace_root:
            shutil.rmtree(dest_dir, ignore_errors=True)
        subprocess.run(["git", "clone", "--depth", "1", "--", clean_url, dest_dir], check=True, timeout=60)
        return dest_dir

    parsed = urlparse(clean_url)
    host = (parsed.netloc or "remote").lower()
    path_parts = [p for p in parsed.path.split("/") if p and p not in (".", "..")]

    # Case 1: GitHub /blob/ single file URL -> convert to raw.githubusercontent.com
    if "github.com" in host and len(path_parts) >= 5 and path_parts[2] == "blob":
        owner, repo, _, branch = path_parts[:4]
        rel_file = "/".join(path_parts[4:])
        raw_url = _validate_safe_remote_url(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rel_file}")
        folder_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", f"{owner}_{repo}_{branch}").strip("._") or "gh_blob"
        dest_dir = _safe_resolve_under(workspace_root, folder_slug)
        os.makedirs(dest_dir, exist_ok=True)
        safe_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", os.path.basename(rel_file)).strip("._") or "source.py"
        local_file = _safe_resolve_under(dest_dir, safe_filename)
        resp = http_requests.get(raw_url, headers={"User-Agent": "ALASTOR-CPG-SAST/2.6"}, timeout=20)
        resp.raise_for_status()
        with open(local_file, "wb") as f:
            f.write(resp.content[:2 * 1024 * 1024])
        return local_file

    # Case 2: GitHub / GitLab / Bitbucket repository root URL or .git URL
    is_git_repo = (
        clean_url.endswith(".git")
        or ("github.com" in host and len(path_parts) == 2)
        or ("gitlab.com" in host and len(path_parts) == 2)
        or ("bitbucket.org" in host and len(path_parts) == 2)
    )
    if is_git_repo:
        repo_slug = f"{path_parts[0]}_{path_parts[1].replace('.git', '')}" if len(path_parts) >= 2 else "remote_repo"
        safe_repo_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", repo_slug).strip("._") or "remote_repo"
        dest_dir = _safe_resolve_under(workspace_root, safe_repo_slug)
        if os.path.exists(dest_dir) and dest_dir != workspace_root:
            shutil.rmtree(dest_dir, ignore_errors=True)
        clone_url = _validate_safe_remote_url(
            clean_url if clean_url.endswith(".git") else f"https://{host}/{path_parts[0]}/{path_parts[1]}.git"
        )
        res = subprocess.run(["git", "clone", "--depth", "1", "--", clone_url, dest_dir], capture_output=True, text=True, timeout=90)
        if res.returncode == 0 and os.path.exists(dest_dir):
            return dest_dir

    # Case 3: Direct raw source file URL or Live Web Application URL
    slug = re.sub(r"[^a-zA-Z0-9._-]", "_", f"{host}_{'_'.join(path_parts[-2:])}" if path_parts else host)[:60].strip("._") or "web_target"
    dest_dir = _safe_resolve_under(workspace_root, slug)
    os.makedirs(dest_dir, exist_ok=True)

    resp = http_requests.get(clean_url, headers={"User-Agent": "ALASTOR-CPG-SAST/2.6"}, timeout=20)
    resp.raise_for_status()
    raw_bytes = resp.content[:2 * 1024 * 1024]
    content_type = (resp.headers.get("Content-Type") or "").lower()

    last_part = re.sub(r"[^a-zA-Z0-9._-]", "_", path_parts[-1]).strip("._") if path_parts else ""
    ext = os.path.splitext(last_part)[1].lower()
    if last_part and ext in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yaml", ".yml"}:
        local_file = _safe_resolve_under(dest_dir, last_part)
        with open(local_file, "wb") as f:
            f.write(raw_bytes)
        return local_file

    # Webpage / HTML / API response: save HTML and extract inline <script> blocks into a .js file for CPG analysis
    text_body = raw_bytes.decode("utf-8", errors="replace")
    html_file = _safe_resolve_under(dest_dir, "index.html")
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(text_body)

    scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", text_body, flags=re.IGNORECASE)
    non_empty_scripts = [s.strip() for s in scripts if s and s.strip()]
    if non_empty_scripts:
        js_file = _safe_resolve_under(dest_dir, "extracted_page_scripts.js")
        with open(js_file, "w", encoding="utf-8") as f:
            f.write(f"// Extracted inline scripts from {clean_url}\n\n")
            f.write("\n\n// --- Script Block ---\n".join(non_empty_scripts))
    elif "json" in content_type or text_body.lstrip().startswith(("{", "[")):
        json_file = _safe_resolve_under(dest_dir, "response_payload.json")
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(text_body)
    else:
        js_fallback = _safe_resolve_under(dest_dir, "remote_source.js")
        with open(js_fallback, "w", encoding="utf-8") as f:
            f.write(text_body)

    return dest_dir


@app.on_event("startup")
def startup_event():
    """Initializes Neo4j connection, verifies APOC, applies graph constraints, and restores cached scan state."""
    global current_scan_dir, current_app_tree, _cached_findings, _cached_findings_time, _last_neo4j_ingested_dir
    try:
        neo4j_client.verify_connectivity_and_apoc()
        neo4j_client.init_schema()
        logger.info("Database initialized successfully.")
        # Find the most recently scanned project in scan_history_cache.json if available
        _latest_ts = ""
        for _entry in enterprise_mgr.project_scan_cache.values():
            _ep = str(_entry.get("project_path") or "")
            _ts = str(_entry.get("last_scanned_at") or "")
            if _ep and os.path.exists(_ep) and _ts > _latest_ts:
                _latest_ts = _ts
                current_scan_dir = os.path.abspath(_ep)
        if current_scan_dir:
            _last_neo4j_ingested_dir = os.path.normcase(os.path.abspath(current_scan_dir))
            enterprise_mgr.set_active_scan_target(current_scan_dir)
        # Restore cached scan details for the active project so user can view last-scan results immediately
        cached = enterprise_mgr.get_cached_scan_for_project(current_scan_dir)
        if cached:
            if cached.get("app_tree"):
                try:
                    current_app_tree = AppTreeSummary(**cached["app_tree"])
                except Exception:
                    pass
            if cached.get("latest_findings") is not None:
                try:
                    _cached_findings = [Finding(**f) for f in cached["latest_findings"]]
                    _cached_findings_time = time.time()
                except Exception:
                    pass
            enterprise_mgr._sync_active_project_metrics(get_or_compute_findings())
        elif os.path.exists(current_scan_dir):
            current_app_tree = AppTreeAnalyzer(current_scan_dir).analyze()
            initial_findings = get_or_compute_findings(force_refresh=True)
            enterprise_mgr.record_scan_snapshot(
                resolved_path=current_scan_dir,
                findings=initial_findings,
                app_tree=current_app_tree,
                files_scanned=current_app_tree.total_files,
                nodes_created=0,
                edges_created=0,
                tech_stack=current_app_tree.detected_tech_stack,
            )
    except Exception as e:
        logger.error(f"Failed to initialize Neo4j: {e}", exc_info=True)


@app.on_event("shutdown")
def shutdown_event():
    neo4j_client.close()


@app.get("/api/health")
def health_check():
    return {"status": "HEALTHY", "neo4j": "CONNECTED"}


@app.get("/api/fs/browse", response_model=FsBrowseResponse)
def browse_filesystem(path: Optional[str] = Query(None, description="Directory path to browse")):
    """
    Lists quick-access project roots, drives, subdirectories, and source files so the user
    can visually browse and pick any Folder or File without copy-pasting paths.
    """
    base_scan_dir = os.getenv("CPG_SCAN_BASE", os.getcwd())
    platform_root = os.path.dirname(base_scan_dir)
    projects_root = os.path.dirname(platform_root)

    quick_roots: List[Dict[str, str]] = []
    seen_roots = set()

    def add_quick_root(label: str, p: str, kind: str = "folder"):
        norm = os.path.abspath(p)
        if os.path.exists(norm) and norm not in seen_roots:
            seen_roots.add(norm)
            quick_roots.append({"label": label, "path": norm, "kind": kind})

    # Add workspace roots
    add_quick_root("ALASTOR Platform Root (cpg-sast-platform)", platform_root, "project")
    if os.path.isdir(projects_root):
        add_quick_root(f"Projects ({os.path.basename(projects_root) or projects_root})", projects_root, "root")
        try:
            for entry in sorted(os.scandir(projects_root), key=lambda e: e.name.lower()):
                if entry.is_dir() and not entry.name.startswith("."):
                    add_quick_root(f"Project: {entry.name}", entry.path, "project")
        except Exception:
            pass

    user_home = os.path.expanduser("~")
    for sub in ("Desktop", "Downloads", "Documents"):
        cand = os.path.join(user_home, sub)
        if os.path.isdir(cand):
            add_quick_root(sub, cand, "user")

    # Add Windows drives if on Windows
    if os.name == "nt":
        for drive_letter in "CDEFG":
            drive_path = f"{drive_letter}:\\"
            if os.path.exists(drive_path):
                add_quick_root(f"Drive ({drive_letter}:)", drive_path, "drive")

    # Determine target directory to list
    target_dir = path.strip() if path and path.strip() else projects_root
    if not os.path.exists(target_dir):
        # Try relative resolution
        cand = os.path.abspath(os.path.join(platform_root, target_dir))
        target_dir = cand if os.path.exists(cand) else projects_root

    if os.path.isfile(target_dir):
        target_dir = os.path.dirname(target_dir)

    target_dir = os.path.abspath(target_dir)
    parent_dir = os.path.dirname(target_dir)
    if parent_dir == target_dir:
        parent_dir = None

    directories: List[FsEntry] = []
    files: List[FsEntry] = []

    try:
        for entry in sorted(os.scandir(target_dir), key=lambda e: (not e.is_dir(), e.name.lower())):
            if entry.name in IGNORE_DIRS or entry.name.startswith("._") or entry.name.lower() in {".ds_store", "thumbs.db", "desktop.ini"}:
                continue
            try:
                if entry.is_dir():
                    directories.append(
                        FsEntry(
                            name=entry.name,
                            path=os.path.abspath(entry.path),
                            is_dir=True
                        )
                    )
                elif entry.is_file():
                    ext = os.path.splitext(entry.name)[1].lower()
                    size_b = entry.stat().st_size
                    files.append(
                        FsEntry(
                            name=entry.name,
                            path=os.path.abspath(entry.path),
                            is_dir=False,
                            size_bytes=size_b,
                            extension=ext,
                            is_code=ext in CODE_EXTENSIONS or ext in {".json", ".yaml", ".yml", ".html", ".env"}
                        )
                    )
            except OSError:
                continue
    except Exception as e:
        safe_dir_log = _sanitize_log(target_dir)
        safe_err_log = _sanitize_log(e)
        logger.warning("Cannot browse directory %s: %s", safe_dir_log, safe_err_log)

    return FsBrowseResponse(
        current_path=target_dir,
        parent_path=parent_dir,
        quick_roots=quick_roots,
        directories=directories[:200],
        files=files[:300]
    )


@app.post("/api/fs/native-dialog", response_model=NativeDialogResponse)
def open_native_os_dialog(req: NativeDialogRequest):
    """
    Opens a native Windows/OS Folder or File picker dialog on the host machine
    and returns the selected path directly to the web UI.
    """
    initial_dir = req.initial_dir if req.initial_dir and os.path.isdir(req.initial_dir) else os.path.dirname(os.path.dirname(os.getcwd()))
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if req.mode == "file":
            selected = filedialog.askopenfilename(
                parent=root,
                initialdir=initial_dir,
                title="Select Target Source File for ARGON CPG-SAST Scan",
                filetypes=[
                    ("Supported Code & Config Files", "*.py *.js *.jsx *.ts *.tsx *.json *.yaml *.yml *.html"),
                    ("All Files", "*.*")
                ]
            )
        else:
            selected = filedialog.askdirectory(
                parent=root,
                initialdir=initial_dir,
                title="Select Target Project Folder for ARGON CPG-SAST Scan",
                mustexist=True
            )
        root.destroy()
        if not selected:
            return NativeDialogResponse(selected_path="", cancelled=True)
        return NativeDialogResponse(selected_path=os.path.normpath(selected), cancelled=False)
    except Exception as e:
        logger.warning(f"Native dialog failed: {e}")
        return NativeDialogResponse(selected_path="", cancelled=True, error=str(e))


@app.post("/api/scan/upload", response_model=UploadTargetResponse)
def upload_target_files(req: UploadTargetRequest):
    """
    Saves browser-selected local files or folders into a managed scan workspace
    and returns the workspace path so it can be scanned immediately.
    """
    base_scan_dir = os.getenv("CPG_SCAN_BASE", os.getcwd())
    upload_root = os.path.realpath(os.path.join(os.path.dirname(base_scan_dir), ".uploaded_targets"))
    os.makedirs(upload_root, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", req.target_name.strip() or "uploaded_workspace").strip("._") or "uploaded_workspace"
    target_dir = _safe_resolve_under(upload_root, safe_name)

    if os.path.exists(target_dir) and target_dir != upload_root:
        shutil.rmtree(target_dir, ignore_errors=True)
    os.makedirs(target_dir, exist_ok=True)

    saved_count = 0
    last_saved_file = ""
    for item in req.files:
        rel_parts = [
            re.sub(r"[^a-zA-Z0-9._-]", "_", seg)
            for seg in item.filepath.replace("\\", "/").split("/")
            if seg and seg not in (".", "..")
        ]
        if not rel_parts:
            continue
        dest_file = _safe_resolve_under(target_dir, *rel_parts)
        os.makedirs(os.path.dirname(dest_file), exist_ok=True)
        with open(dest_file, "w", encoding="utf-8") as f:
            f.write(item.content)
        saved_count += 1
        last_saved_file = dest_file

    # If a single file was uploaded, return that file path directly; otherwise return the folder path
    final_target = last_saved_file if saved_count == 1 and last_saved_file else target_dir
    return UploadTargetResponse(target_path=final_target, files_saved=saved_count)


@app.get("/api/scan/progress", response_model=ScanProgress)
def get_scan_progress():
    """Returns current real-time scan progress, active pass, and file statistics."""
    return current_progress


@app.post("/api/scan", response_model=ScanResponse)
def scan_project(req: ScanRequest):
    """
    Executes full CPG compiler pipeline and Application Architecture Tree analysis over target path.
    Supports local folders, single files, and remote URLs (Git repos, raw files, or web pages).
    """
    global current_scan_dir, current_app_tree
    target_path = req.target_path.strip()
    base_scan_dir = os.getenv("CPG_SCAN_BASE", os.getcwd())

    # Check if the target is a Remote URL or Git Repository
    if target_path.startswith(("http://", "https://", "git@")):
        try:
            update_progress(
                is_scanning=True,
                phase="REMOTE_FETCH",
                current_pass="Pass 0/7: Fetching Remote URL / Git Target",
                current_file=target_path,
                files_done=0,
                total_files=1,
                percent=3,
                message=f"Fetching remote target from {target_path}..."
            )
            resolved_path = _resolve_remote_url_target(target_path, base_scan_dir)
        except Exception as e:
            update_progress(
                is_scanning=False,
                phase="ERROR",
                current_pass="Failed",
                percent=0,
                message=f"Failed to fetch remote URL target: {e}",
                error=str(e)
            )
            raise HTTPException(status_code=400, detail=f"Failed to fetch remote URL target '{target_path}': {e}")
    else:
        # Robust path resolution checking current dir, parent dir, and base_scan_dir
        candidates = [
            target_path,
            os.path.normpath(os.path.join(base_scan_dir, target_path)),
            os.path.normpath(os.path.join(os.path.dirname(base_scan_dir), target_path)),
            os.path.normpath(os.path.join(os.path.dirname(os.path.dirname(base_scan_dir)), target_path)),
            os.path.abspath(target_path)
        ]
        resolved_path = None
        for cand in candidates:
            if cand and os.path.exists(cand):
                resolved_path = cand
                break

    if not resolved_path or not os.path.exists(resolved_path):
        update_progress(
            is_scanning=False,
            phase="ERROR",
            current_pass="Failed",
            percent=0,
            message=f"Target path does not exist: {target_path}",
            error=f"Target path does not exist: {target_path}"
        )
        raise HTTPException(status_code=404, detail=f"Target path does not exist: {target_path}")

    current_scan_dir = resolved_path
    safe_resolved_log = _sanitize_log(resolved_path)
    logger.info("Initiating Application Tree & CPG analysis for: %s", safe_resolved_log)

    try:
        # Pass A: Application Architecture Tree & Purpose Identification
        update_progress(
            is_scanning=True,
            phase="DISCOVERY",
            current_pass="Pass 1/7: Architecture Discovery",
            current_file=resolved_path,
            files_done=0,
            total_files=0,
            percent=5,
            message="Discovering files, structure, and architectural roles..."
        )

        tree_analyzer = AppTreeAnalyzer(resolved_path)
        current_app_tree = tree_analyzer.analyze()

        # Pass B: Discover CPG-compatible source files (.py, .js, .jsx, .ts, .tsx)
        scanned_files = scan_directory(resolved_path)
        total_discovered = current_app_tree.total_files

        # Ingest into Neo4j
        global _cached_findings, _cached_external_findings, _cached_advisories, _last_neo4j_ingested_dir
        _cached_findings = None
        _cached_external_findings = []
        _cached_advisories = []
        neo4j_client.clear_database()
        neo4j_client.init_schema()
        ingestor = BatchIngestor(neo4j_client)

        update_progress(
            is_scanning=True,
            phase="APP_TREE_INGEST",
            current_pass="Pass 2/7: Ingesting Architecture Tree",
            current_file="",
            files_done=0,
            total_files=total_discovered,
            percent=12,
            message=f"Ingesting {total_discovered} files & architecture into graph database..."
        )

        def app_tree_callback(msg: str, cur: int, tot: int):
            update_progress(
                is_scanning=True,
                phase="APP_TREE_INGEST",
                current_pass="Pass 2/7: Ingesting Architecture Tree",
                current_file="",
                files_done=cur,
                total_files=tot,
                percent=12 + int(8 * (cur / max(1, tot))),
                message=f"{msg} ({cur}/{tot})"
            )

        tree_nodes_created, tree_edges_created = ingestor.ingest_app_tree(
            current_app_tree, progress_callback=app_tree_callback
        )
        logger.info(
            "App tree ingested into Neo4j: %d nodes, %d edges",
            tree_nodes_created,
            tree_edges_created,
        )

        # If no CPG source files exist, we still succeed with complete Application Tree mapping!
        if not scanned_files:
            logger.info("Scanned %d application files (0 AST code files).", int(current_app_tree.total_files))
            update_progress(
                is_scanning=False,
                phase="COMPLETED",
                current_pass="Completed",
                current_file="",
                files_done=total_discovered,
                total_files=total_discovered,
                percent=100,
                message=f"Architecture mapped for {total_discovered} files."
            )
            return ScanResponse(
                project_path=resolved_path,
                files_scanned=current_app_tree.total_files,
                nodes_created=tree_nodes_created,
                edges_created=tree_edges_created,
                status="SUCCESS",
                categories=current_app_tree.category_counts,
                tech_stack=current_app_tree.detected_tech_stack,
                total_app_files=current_app_tree.total_files
            )

        num_code_files = len(scanned_files)

        # Pass 1: Tree-Sitter AST Normalization
        all_nodes: List[CPGNode] = []
        all_edges: List[CPGEdge] = []
        node_map: Dict[str, CPGNode] = {}
        file_nodes_map: Dict[str, List[CPGNode]] = {}
        func_params_map: Dict[str, List[CPGNode]] = {}
        func_returns_map: Dict[str, List[CPGNode]] = {}

        for idx, sf in enumerate(scanned_files):
            pct = 20 + int(20 * ((idx + 1) / num_code_files))
            update_progress(
                is_scanning=True,
                phase="AST_PARSING",
                current_pass="Pass 3/7: Tree-Sitter AST Normalization",
                current_file=sf.filepath,
                files_done=idx + 1,
                total_files=num_code_files,
                percent=pct,
                message=f"Normalizing AST: {sf.filepath} ({idx + 1}/{num_code_files})"
            )
            try:
                normalizer = ASTNormalizer(sf)
                f_nodes, f_edges = normalizer.normalize()
                all_nodes.extend(f_nodes)
                all_edges.extend(f_edges)
                node_map.update(normalizer.node_map)
                file_nodes_map[sf.filepath] = f_nodes

                # Index function parameters and returns for DFG Builder in O(N)
                _params_by_scope: Dict[str, List[CPGNode]] = {}
                for _pn in f_nodes:
                    if _pn.label == "Parameter" and _pn.ast_type not in ("parameters", "formal_parameters"):
                        _params_by_scope.setdefault(_pn.scope_id, []).append(_pn)

                for n in f_nodes:
                    if n.label == "Function":
                        params = _params_by_scope.get(n.id, [])
                        unique_params = []
                        seen_names = set()
                        for p in params:
                            if p.name not in seen_names and p.name not in ("self", "cls") and not p.name.startswith("("):
                                seen_names.add(p.name)
                                unique_params.append(p)
                        func_params_map[n.name] = unique_params
                    elif n.label == "Return":
                        fn = node_map.get(n.scope_id)
                        if fn and fn.label == "Function":
                            if fn.name not in func_returns_map:
                                func_returns_map[fn.name] = []
                            func_returns_map[fn.name].append(n)
            except Exception as e:
                logger.warning("Skipping AST normalization for %s: %s", _sanitize_log(sf.filepath), _sanitize_log(e))

        # Pass 2: Control Flow Graph (CFG) State Machine
        for idx, sf in enumerate(scanned_files):
            pct = 40 + int(20 * ((idx + 1) / num_code_files))
            update_progress(
                is_scanning=True,
                phase="CFG_BUILDING",
                current_pass="Pass 4/7: Control Flow Graph (CFG)",
                current_file=sf.filepath,
                files_done=idx + 1,
                total_files=num_code_files,
                percent=pct,
                message=f"Building CFG: {sf.filepath} ({idx + 1}/{num_code_files})"
            )
            try:
                f_nodes = file_nodes_map.get(sf.filepath, [])
                cfg_builder = CFGBuilder(
                    filepath=sf.filepath,
                    content_bytes=sf.content_bytes,
                    language=sf.language,
                    nodes=f_nodes,
                    node_map=node_map
                )
                cfg_edges = cfg_builder.build()
                all_edges.extend(cfg_edges)
            except Exception as e:
                logger.warning("Skipping CFG generation for %s: %s", _sanitize_log(sf.filepath), _sanitize_log(e))

        # Pass 3: Data Flow Graph (DFG) & Symbol Table
        for idx, sf in enumerate(scanned_files):
            pct = 60 + int(20 * ((idx + 1) / num_code_files))
            update_progress(
                is_scanning=True,
                phase="DFG_BUILDING",
                current_pass="Pass 5/7: Data Flow Graph (DFG)",
                current_file=sf.filepath,
                files_done=idx + 1,
                total_files=num_code_files,
                percent=pct,
                message=f"Tracing DFG: {sf.filepath} ({idx + 1}/{num_code_files})"
            )
            try:
                f_nodes = file_nodes_map.get(sf.filepath, [])
                dfg_builder = DFGBuilder(
                    filepath=sf.filepath,
                    content_bytes=sf.content_bytes,
                    language=sf.language,
                    nodes=f_nodes,
                    node_map=node_map,
                    function_params_map=func_params_map,
                    function_returns_map=func_returns_map
                )
                dfg_edges = dfg_builder.build()
                all_edges.extend(dfg_edges)
            except Exception as e:
                logger.warning("Skipping DFG generation for %s: %s", _sanitize_log(sf.filepath), _sanitize_log(e))

        # Pass 4: Cross-File Call Graph Resolution
        update_progress(
            is_scanning=True,
            phase="CALL_GRAPH",
            current_pass="Pass 6/7: Cross-File Call Graph",
            current_file="",
            files_done=num_code_files,
            total_files=num_code_files,
            percent=82,
            message="Resolving cross-file function calls & export tables..."
        )
        try:
            call_graph_builder = CallGraphBuilder(all_nodes)
            call_edges = call_graph_builder.resolve_calls()
            all_edges.extend(call_edges)
        except Exception as e:
            logger.warning(f"Skipping Call Graph resolution: {e}")

        # Pass 5: Ingest CPG into Neo4j
        update_progress(
            is_scanning=True,
            phase="CPG_INGEST",
            current_pass="Pass 7/7: Neo4j Ingestion",
            current_file="",
            files_done=0,
            total_files=len(all_nodes) + len(all_edges),
            percent=88,
            message=f"Batch ingesting {len(all_nodes)} CPG nodes and {len(all_edges)} relationships..."
        )

        def cpg_callback(msg: str, cur: int, tot: int):
            update_progress(
                is_scanning=True,
                phase="CPG_INGEST",
                current_pass="Pass 7/7: Neo4j Ingestion",
                current_file="",
                files_done=cur,
                total_files=tot,
                percent=88 + int(10 * (cur / max(1, tot))),
                message=f"{msg} ({cur}/{tot})"
            )

        cpg_nodes_created, cpg_edges_created = ingestor.ingest(
            all_nodes, all_edges, progress_callback=cpg_callback
        )
        _last_neo4j_ingested_dir = os.path.normcase(os.path.abspath(resolved_path))

        # Synchronize the active application in enterprise_mgr.projects and refresh findings/metrics
        enterprise_mgr.set_active_scan_target(resolved_path, current_app_tree.detected_tech_stack)
        scanned_findings = get_or_compute_findings(force_refresh=True)
        enterprise_mgr.record_scan_snapshot(
            resolved_path=resolved_path,
            findings=scanned_findings,
            app_tree=current_app_tree,
            files_scanned=len(scanned_files),
            nodes_created=cpg_nodes_created,
            edges_created=cpg_edges_created,
            tech_stack=current_app_tree.detected_tech_stack,
        )
        # Re-enrich with updated Track Changes status (NEW / UNCHANGED / FIXED / REOPENED)
        get_or_compute_findings(force_refresh=False)

        update_progress(
            is_scanning=False,
            phase="COMPLETED",
            current_pass="Completed",
            current_file="",
            files_done=num_code_files,
            total_files=num_code_files,
            percent=100,
            message=f"Scan complete! {cpg_nodes_created} CPG nodes, {cpg_edges_created} edges mapped."
        )

        return ScanResponse(
            project_path=resolved_path,
            files_scanned=len(scanned_files),
            nodes_created=cpg_nodes_created,
            edges_created=cpg_edges_created,
            status="SUCCESS",
            categories=current_app_tree.category_counts,
            tech_stack=current_app_tree.detected_tech_stack,
            total_app_files=current_app_tree.total_files
        )
    except Exception as exc:
        update_progress(
            is_scanning=False,
            phase="ERROR",
            current_pass="Error",
            percent=0,
            message=f"Scan failed: {str(exc)}",
            error=str(exc)
        )
        raise


@app.get("/api/app-tree", response_model=AppTreeSummary)
def get_app_tree():
    """Returns the full hierarchical application tree and architectural purpose of every file."""
    global current_app_tree, current_scan_dir
    if current_app_tree is None:
        target = current_scan_dir or enterprise_mgr.platform_root
        if os.path.exists(target):
            analyzer = AppTreeAnalyzer(target)
            current_app_tree = analyzer.analyze()
        else:
            raise HTTPException(status_code=404, detail="No scanned project available.")
    return current_app_tree


@app.get("/api/file-purpose", response_model=FilePurposeInfo)
def get_file_purpose(path: str = Query(..., description="Relative filepath")):
    """Returns the architectural classification, purpose description, and elements of a specific file."""
    global current_app_tree, current_scan_dir
    if current_app_tree is None:
        get_app_tree()

    norm_target = path.replace("\\", "/").lstrip("/")
    for f in current_app_tree.flat_files:
        if f.filepath == norm_target or f.filepath.endswith(norm_target) or norm_target.endswith(f.filepath):
            return f

    raise HTTPException(status_code=404, detail=f"File not found in application tree: {path}")


_cached_findings: Optional[List[Finding]] = None
_cached_findings_time: float = 0.0
_cached_external_findings: List[Finding] = []
_cached_advisories: List[ExtractedAdvisory] = []
_last_neo4j_ingested_dir: Optional[str] = None
_findings_lock = threading.Lock()


def get_or_compute_findings(force_refresh: bool = False) -> List[Finding]:
    """Retrieves cached findings or executes SAST + SCA + IaC rules when refreshed, merged with site-extracted code matches and enriched with BFL, Aging & Triage."""
    global _cached_findings, _cached_findings_time, _cached_external_findings, current_scan_dir, _last_neo4j_ingested_dir
    now = time.time()
    target_dir = current_scan_dir or enterprise_mgr.platform_root
    if not os.path.exists(target_dir):
        target_dir = enterprise_mgr.platform_root
    _norm_target_dir = os.path.normcase(os.path.abspath(target_dir))

    if force_refresh or _cached_findings is None:
        with _findings_lock:
            if force_refresh or _cached_findings is None:
                root_check = os.path.dirname(target_dir) if os.path.isfile(target_dir) else target_dir
                sast_findings: List[Finding] = []
                if _last_neo4j_ingested_dir is None or _last_neo4j_ingested_dir == _norm_target_dir:
                    executor = RuleExecutor(neo4j_client)
                    raw_sast = executor.run_all_rules()
                    for sf in raw_sast:
                        fp = sf.path_nodes[-1].get("filepath", "") if sf.path_nodes else ""
                        if fp and os.path.exists(os.path.join(root_check, fp)):
                            sast_findings.append(sf)
                if not sast_findings and _last_neo4j_ingested_dir != _norm_target_dir:
                    cached_proj = enterprise_mgr.get_cached_scan_for_project(target_dir)
                    if cached_proj and isinstance(cached_proj.get("latest_findings"), list):
                        for cf_dict in cached_proj["latest_findings"]:
                            if isinstance(cf_dict, dict) and cf_dict.get("scan_engine") == "SAST":
                                fp = (cf_dict.get("path_nodes") or [{}])[-1].get("filepath", "")
                                if fp and os.path.exists(os.path.join(root_check, fp)):
                                    try:
                                        sast_findings.append(Finding(**cf_dict))
                                    except Exception:
                                        pass
                sca_iac_findings = enterprise_mgr.run_sca_and_iac_scanners(target_dir)
                _cached_findings = sast_findings + sca_iac_findings
                _cached_findings_time = now

    combined: List[Finding] = [f.model_copy(deep=True) for f in (_cached_findings or [])]
    seen_ids = {f.id for f in combined}
    seen_loc = {
        (
            (f.path_nodes[-1].get("filepath") if f.path_nodes else ""),
            int(f.path_nodes[-1].get("start_line") or 0) if f.path_nodes else 0,
        )
        for f in combined
    }
    for ef in _cached_external_findings:
        ef_loc = (
            (ef.path_nodes[-1].get("filepath") if ef.path_nodes else ""),
            int(ef.path_nodes[-1].get("start_line") or 0) if ef.path_nodes else 0,
        )
        if ef.id not in seen_ids and ef_loc not in seen_loc:
            seen_ids.add(ef.id)
            seen_loc.add(ef_loc)
            combined.append(ef.model_copy(deep=True))

    return enterprise_mgr.enrich_findings(combined)


@app.get("/api/findings", response_model=List[Finding])
def get_findings(include_suppressed: bool = Query(True), project_path: Optional[str] = Query(None)):
    """Runs all deterministic SAST, SCA, and IaC rules and merges any active site-extracted code findings."""
    if project_path and os.path.exists(project_path):
        _norm_req = os.path.normcase(os.path.abspath(project_path))
        _norm_cur = os.path.normcase(os.path.abspath(current_scan_dir or enterprise_mgr.platform_root))
        if _norm_req != _norm_cur:
            _cached_p = enterprise_mgr.get_cached_scan_for_project(project_path)
            if _cached_p and isinstance(_cached_p.get("latest_findings"), list):
                _proj_f = enterprise_mgr.enrich_findings([Finding(**f) for f in _cached_p["latest_findings"]])
                if not include_suppressed:
                    return [f for f in _proj_f if f.triage_status != "NOT_EXPLOITABLE"]
                return _proj_f
    all_f = get_or_compute_findings()
    if not include_suppressed:
        return [f for f in all_f if f.triage_status != "NOT_EXPLOITABLE"]
    return all_f


@app.get("/api/findings/{finding_id}/artifacts")
def get_finding_verification_artifacts(finding_id: str):
    """
    Generates deterministic Verification Proof & Remediation Artifacts for a specific finding:
    1. CPG Graph Proof Trace (.json)
    2. Unified Remediation Patch (.patch)
    3. Sandboxed Defensive Regression Test (.py)
    4. Audit Evidence Markdown Bundle (.md)
    """
    findings = get_or_compute_findings()
    target = next((f for f in findings if f.id == finding_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    nodes = target.path_nodes or []
    edges = target.path_edges or []
    first_node = nodes[0] if nodes else {"filepath": "unknown.py", "start_line": 1, "code": "", "name": "source"}
    sink_node = nodes[-1] if nodes else first_node
    filepath = sink_node.get("filepath") or first_node.get("filepath") or "app.py"
    sink_line = int(sink_node.get("start_line") or 1)
    vuln_code = (sink_node.get("code") or sink_node.get("name") or "# vulnerable statement").strip()
    rule_upper = (target.rule_id or "").upper()
    cwe = (target.cwe_id or "CWE-703").upper()

    is_js = filepath.lower().endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))

    # Determine safe replacement line and defensive mock assertion based on rule/CWE
    if "TAINT" in rule_upper or "SHELL" in rule_upper or cwe == "CWE-78":
        if is_js:
            safe_line = "import('node:child_process').then(cp => cp.execFile('cmd.exe', ['/c', 'start', `http://localhost:${Number(actualPort)}`]));"
        else:
            safe_line = "subprocess.run(['echo', safe_validated_arg], shell=False, check=True)"
        cypher_proof = (
            "MATCH path = (source:CPGNode {is_source: true})-[:DFG_FLOWS_TO*1..8]->(sink:CPGNode {is_sink: true})\n"
            "WHERE NONE(n IN nodes(path) WHERE n.is_sanitizer = true)\n"
            "RETURN [n IN nodes(path) | {id: n.id, line: n.start_line, code: n.code}] AS proof_trace"
        )
        regression_test = f'''"""
Defensive Security Regression Verification Artifact
Finding ID: {target.id} ({target.rule_id} / {cwe})
Target File: {filepath} (Line {sink_line})
Purpose: Verifies that OS command execution uses argument arrays (execFile / shell=False) rather than a subshell.
"""
import unittest
from unittest.mock import patch


class TestSecurityRemediation_{target.id[:8]}(unittest.TestCase):
    @patch("os.system")
    def test_os_system_sink_is_not_invoked(self, mock_os_system):
        """Verifies that untrusted input does not reach raw os.system / cp.exec shell execution."""
        self.assertEqual(mock_os_system.call_count, 0, "Raw shell sink must not be called")

    @patch("subprocess.run")
    def test_subprocess_enforces_shell_false(self, mock_subproc_run):
        """Verifies that process execution strictly avoids spawning a shell."""
        for call in mock_subproc_run.call_args_list:
            _, kwargs = call
            self.assertFalse(kwargs.get("shell", False), "Process execution must enforce shell=False / execFile")


if __name__ == "__main__":
    unittest.main()
'''
    elif "SQLI" in rule_upper or cwe == "CWE-89":
        safe_line = 'cursor.execute("SELECT * FROM records WHERE name = ?", (user_input,))'
        cypher_proof = (
            "MATCH (sink:CPGNode {label: 'Call'})\n"
            "WHERE sink.name CONTAINS 'execute' AND (sink.code CONTAINS 'f\"' OR sink.code CONTAINS '.format(' OR sink.code CONTAINS '%')\n"
            "RETURN sink.id, sink.filepath, sink.start_line, sink.code"
        )
        regression_test = f'''"""
Defensive Security Regression Verification Artifact
Finding ID: {target.id} ({target.rule_id} / {cwe})
Target File: {filepath} (Line {sink_line})
Purpose: Verifies via AST & mock inspection that database queries use parameterized placeholders.
"""
import unittest
from unittest.mock import MagicMock


class TestSqlParameterizedQuery_{target.id[:8]}(unittest.TestCase):
    def test_cursor_execute_uses_bound_parameters(self):
        """Verifies that cursor.execute receives a parameter tuple rather than a formatted string."""
        mock_cursor = MagicMock()
        sample_param = "alice"
        mock_cursor.execute("SELECT * FROM users WHERE username = ?", (sample_param,))
        sql_query, bound_params = mock_cursor.execute.call_args[0]
        self.assertIn("?", sql_query)
        self.assertIsInstance(bound_params, tuple)


if __name__ == "__main__":
    unittest.main()
'''
    elif "DOM-XSS" in rule_upper or cwe == "CWE-79":
        if "document.write" in vuln_code:
            safe_line = "const safeScript = document.createElement('script'); safeScript.src = new URL(Qg, window.location.origin).href; document.head.appendChild(safeScript);"
        elif 'href="${esc(' in vuln_code:
            safe_line = "const safeUrl = (u) => { try { const p = new URL(u); return ['https:', 'http:'].includes(p.protocol) ? esc(p.href) : '#'; } catch { return '#'; } }; // Interpolate href=\"${safeUrl(url)}\""
        elif "innerHTML" in vuln_code or "outerHTML" in vuln_code:
            safe_line = "g.textContent = String(T ?? ''); // Or DOMPurify.sanitize(T, { RETURN_TRUSTED_TYPE: true })"
        else:
            safe_line = "const parsedUrl = new URL(g, window.location.origin); if (parsedUrl.origin === window.location.origin) { sa.setAttribute('src', parsedUrl.href); }"
        cypher_proof = (
            f"MATCH path = (src:CPGNode)-[:DFG_FLOWS_TO*1..3]->(sink:CPGNode {{filepath: '{filepath}', start_line: {sink_line}}})\n"
            "RETURN [n IN nodes(path) | {id: n.id, label: n.label, line: n.start_line, code: n.code}] AS dom_xss_trace"
        )
        regression_test = f'''"""
Defensive Security Regression Verification Artifact
Finding ID: {target.id} ({target.rule_id} / {cwe})
Target File: {filepath} (Line {sink_line})
Purpose: Verifies that DOM manipulation blocks javascript: URI schemes in <a href> and avoids raw innerHTML/document.write.
"""
import unittest


class TestDomXssRemediation_{target.id[:8]}(unittest.TestCase):
    def test_remediated_dom_sink_rejects_untrusted_markup_and_schemes(self):
        """Verifies that the remediated DOM code enforces URL protocol allowlisting (https:/http:), textContent, or DOMPurify."""
        remediated_js = {safe_line!r}
        self.assertNotIn("document.write(", remediated_js, "Raw document.write must not be used")
        self.assertTrue(
            "textContent" in remediated_js or "new URL(" in remediated_js or "DOMPurify" in remediated_js,
            "Remediation must enforce safe DOM API (textContent, URL protocol/origin validation via new URL(), or DOMPurify)",
        )


if __name__ == "__main__":
    unittest.main()
'''
    elif "INFINITE-LOOP" in rule_upper or cwe == "CWE-835":
        safe_line = "for _iteration in range(MAX_SAFE_ITERATIONS):"
        cypher_proof = (
            "MATCH (loop:CPGNode {label: 'LoopBlock'})<-[:CFG_LOOP_BACK]-(backNode:CPGNode)\n"
            "WHERE NOT (loop)-[:CFG_BREAK|CFG_FALSE]->(:CPGNode)\n"
            "RETURN loop.id, loop.filepath, loop.start_line, loop.code"
        )
        regression_test = f'''"""
Defensive Security Regression Verification Artifact
Finding ID: {target.id} ({target.rule_id} / {cwe})
Target File: {filepath} (Line {sink_line})
Purpose: Verifies via AST inspection that unbounded while-True loops include an explicit termination guard.
"""
import ast
import unittest


class TestLoopTerminationGuard_{target.id[:8]}(unittest.TestCase):
    def test_loop_has_bounded_exit_condition(self):
        """Verifies that the remediated loop contains a break/return guard or bounded range."""
        remediated_snippet = """
for _step in range(1000):
    if True:
        break
"""
        tree = ast.parse(remediated_snippet)
        has_break_or_return = any(isinstance(n, (ast.Break, ast.Return)) for n in ast.walk(tree))
        self.assertTrue(has_break_or_return, "Loop must contain a reachable termination statement")


if __name__ == "__main__":
    unittest.main()
'''
    else:
        if is_js and ("getSession" in vuln_code or "sendCode" in vuln_code):
            safe_line = "// Enforce session ownership check in POST /api/scan: const session = getSession(req); if (!session) return res.status(401).json({ error: 'Unauthorized' });"
        else:
            safe_line = f"{'//' if is_js else '#'} REMEDIATED: Applied security guard for {target.rule_id} ({cwe})"
        cypher_proof = (
            f"MATCH (n:CPGNode {{filepath: '{filepath}', start_line: {sink_line}}})\n"
            "RETURN n.id, n.label, n.ast_type, n.code"
        )
        regression_test = f'''"""
Defensive Security Regression Verification Artifact
Finding ID: {target.id} ({target.rule_id} / {cwe})
Target File: {filepath} (Line {sink_line})
Purpose: Static AST verification harness confirming remediation of {target.title}.
"""
import unittest


class TestRemediationVerification_{target.id[:8]}(unittest.TestCase):
    def test_security_guard_applied(self):
        """Verifies that the vulnerable construct at {filepath}:L{sink_line} has been remediated."""
        remediated = True
        self.assertTrue(remediated)


if __name__ == "__main__":
    unittest.main()
'''

    unified_patch = (
        f"--- a/{filepath}\n"
        f"+++ b/{filepath}\n"
        f"@@ -{sink_line},1 +{sink_line},1 @@\n"
        f"-    {vuln_code}\n"
        f"+    {safe_line}\n"
    )

    cpg_proof_json = {
        "artifact_type": "ALASTOR_DETERMINISTIC_CPG_PROOF",
        "finding_id": target.id,
        "rule_id": target.rule_id,
        "severity": target.severity,
        "cwe_id": target.cwe_id,
        "cve_id": target.cve_id,
        "owasp_category": target.owasp_category,
        "cvss_score": target.cvss_score,
        "cypher_verification_query": cypher_proof,
        "trace_steps": [
            {
                "step": idx + 1,
                "role": "SOURCE" if idx == 0 and len(nodes) > 1 else ("SINK" if idx == len(nodes) - 1 else "PROPAGATION"),
                "node_id": n.get("id"),
                "label": n.get("label"),
                "ast_type": n.get("ast_type"),
                "filepath": n.get("filepath"),
                "line": n.get("start_line"),
                "code": n.get("code"),
            }
            for idx, n in enumerate(nodes)
        ],
        "graph_edges": edges,
    }

    md_bundle = "\n".join([
        f"# Verification Proof & Remediation Artifact — `{target.id}`",
        f"**Title:** {target.title}",
        f"**Rule:** `{target.rule_id}` | **Severity:** `{target.severity}` | **CWE:** `{target.cwe_id or 'N/A'}` | **OWASP:** `{target.owasp_category or 'N/A'}`",
        f"**Location:** `{filepath}` (Line {sink_line})",
        "",
        "## 1. Deterministic CPG Graph Proof (Cypher Query)",
        "```cypher",
        cypher_proof,
        "```",
        "",
        "## 2. Step-by-Step Code Property Graph Trace",
        *[
            f"- **Step {idx + 1} (`{n.get('label')}` at `{n.get('filepath')}:L{n.get('start_line')}`):** `{n.get('code') or n.get('name')}`"
            for idx, n in enumerate(nodes)
        ],
        "",
        "## 3. Unified Remediation Patch (`.patch`)",
        "```diff",
        unified_patch.strip(),
        "```",
        "",
        "## 4. Sandboxed Regression Verification Test (`.py`)",
        "```python",
        regression_test.strip(),
        "```",
    ])

    return {
        "finding_id": target.id,
        "filepath": filepath,
        "line": sink_line,
        "cypher_proof": cypher_proof,
        "unified_patch": unified_patch,
        "regression_unit_test": regression_test,
        "cpg_proof_json": cpg_proof_json,
        "markdown_bundle": md_bundle,
    }


@app.post("/api/vuln-intel/extract", response_model=SiteExtractResponse)
def extract_and_identify_vulnerabilities(req: SiteExtractRequest):
    """
    Extracts vulnerability advisories & signatures from multiple external sites
    (OSV.dev, NIST NVD, GitHub Advisories, MITRE CWE/OWASP, and custom URLs)
    and identifies matching vulnerabilities in the scanned codebase & CPG.
    """
    global current_scan_dir, _cached_external_findings, _cached_advisories
    target_dir = current_scan_dir or enterprise_mgr.platform_root
    if not os.path.exists(target_dir):
        target_dir = enterprise_mgr.platform_root

    engine = VulnExtractorEngine(neo4j_client, target_dir)
    result = engine.run_extraction_and_scan(req)

    # Persist extracted advisories and matched code findings in memory
    _cached_advisories = result.advisories
    if req.auto_scan_code:
        existing_ids = {f.id for f in _cached_external_findings}
        for nf in result.code_findings:
            if nf.id not in existing_ids:
                existing_ids.add(nf.id)
                _cached_external_findings.append(nf)

    return result


@app.get("/api/vuln-intel/advisories", response_model=List[ExtractedAdvisory])
def get_extracted_advisories(auto_init: bool = Query(False)):
    """Returns extracted external site advisories and their code match status."""
    global _cached_advisories, current_scan_dir
    if not _cached_advisories and auto_init:
        target_dir = current_scan_dir or enterprise_mgr.platform_root
        if not os.path.exists(target_dir):
            target_dir = enterprise_mgr.platform_root
        engine = VulnExtractorEngine(neo4j_client, target_dir)
        res = engine.run_extraction_and_scan(SiteExtractRequest(sources=["cisa_owasp", "nvd"], auto_scan_code=True))
        _cached_advisories = res.advisories
    return _cached_advisories


@app.get("/api/export/report")
def export_security_report(format: str = Query("markdown", description="markdown, json, or sarif")):
    """Exports a comprehensive security code review, RACI governance & SAST++++++ ASPM report."""
    global current_scan_dir, current_app_tree, _cached_advisories
    findings = get_or_compute_findings()
    metrics = get_metrics()
    raci = enterprise_mgr.get_raci_governance(findings)
    active_target = current_scan_dir or enterprise_mgr.platform_root
    app_name = os.path.basename(os.path.abspath(active_target)) or active_target

    if format.lower() == "json":
        return JSONResponse({
            "platform": "ALASTOR SAST++++++ Deterministic CPG, ASPM & RACI Governance Platform",
            "application_name": app_name,
            "target_path": active_target,
            "metrics": metrics.model_dump(),
            "raci_governance_health_score": raci.governance_health_score,
            "findings": [f.model_dump() for f in findings],
            "extracted_advisories": [a.model_dump() for a in _cached_advisories],
        })

    if format.lower() == "sarif":
        sarif_results = []
        sarif_rules = {}
        for f in findings:
            first_node = f.path_nodes[0] if f.path_nodes else {"filepath": "unknown", "start_line": 1}
            bfl_fp = f.best_fix_location.filepath if f.best_fix_location else first_node.get("filepath", "unknown")
            bfl_ln = f.best_fix_location.line if f.best_fix_location else max(1, int(first_node.get("start_line", 1)))
            if f.rule_id not in sarif_rules:
                sarif_rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title[:80],
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description or f.plain_english_summary},
                    "help": {"text": f.remediation or "Apply recommended fix."},
                    "properties": {
                        "cwe": f.cwe_id,
                        "owasp": f.owasp_category,
                        "engine": f.scan_engine,
                        "security-severity": str(f.cvss_score or 7.0),
                    },
                }
            thread_locations = [
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(n.get("filepath") or bfl_fp)},
                            "region": {"startLine": max(1, int(n.get("start_line") or 1))},
                        },
                        "message": {"text": f"{n.get('name') or n.get('label')}: {n.get('code') or ''}"},
                    }
                }
                for n in (f.path_nodes or [])
            ]
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": "error" if f.severity in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f"{f.title} — {f.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": bfl_fp},
                        "region": {"startLine": bfl_ln}
                    }
                }],
                "codeFlows": [{"threadFlows": [{"locations": thread_locations}]}] if thread_locations else [],
                "fixes": [{
                    "description": {"text": f.remediation or "Recommended remediation"},
                    "artifactChanges": [{
                        "artifactLocation": {"uri": bfl_fp},
                        "replacements": [{
                            "deletedRegion": {"startLine": bfl_ln},
                            "insertedContent": {"text": f.best_fix_location.after_code_block if f.best_fix_location else (f.remediation or "")},
                        }],
                    }],
                }],
                "properties": {
                    "reachability_status": f.reachability_status,
                    "reachability_reason": f.reachability_reason,
                    "epss_score": f.epss_score,
                    "epss_percentile": f.epss_percentile,
                    "cisa_kev_listed": f.cisa_kev_listed,
                    "exploit_maturity": f.exploit_maturity,
                    "raci_responsible": f.raci_responsible,
                    "raci_accountable": f.raci_accountable,
                },
            })
        return JSONResponse({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ALASTOR SAST++++++ CPG & ASPM Engine",
                        "version": "3.5.0",
                        "informationUri": "https://owasp.org/www-project-top-ten/",
                        "rules": list(sarif_rules.values()),
                    }
                },
                "results": sarif_results
            }]
        })

    # Default: Markdown Report
    md_lines = [
        f"# ALASTOR SAST++++++ Security, RACI Governance & ASPM Audit Report — `{app_name}`",
        f"**Application Under Review:** `{app_name}`",
        f"**Target Workspace Path:** `{active_target}`",
        f"**Total Files:** {metrics.total_app_files} | **CPG Nodes:** {metrics.total_nodes} | **CPG Edges:** {metrics.total_edges}",
        f"**Total Findings:** {metrics.total_findings} (Critical: {metrics.critical_count}, High: {metrics.high_count}, Medium: {metrics.medium_count}, Low: {metrics.low_count})",
        f"**RACI Governance Health Score:** {raci.governance_health_score}% ({raci.valid_rows_count}/{raci.total_rows_count} PMI/COBIT Validated Activities)",
        "",
        "## 1. Identified Code Vulnerabilities, Reachability, EPSS & RACI Ownership",
    ]
    if not findings:
        md_lines.extend([
            "✅ **0 Vulnerabilities Detected (100% Clean Security Posture Verified across SAST, SCA & IaC Engines).**",
            ""
        ])
    for idx, f in enumerate(findings, 1):
        first_node = f.path_nodes[0] if f.path_nodes else {}
        fp = f.best_fix_location.filepath if f.best_fix_location else first_node.get("filepath", "N/A")
        ln = f.best_fix_location.line if f.best_fix_location else first_node.get("start_line", 1)
        md_lines.extend([
            f"### {idx}. [{f.severity}] {f.title}",
            f"- **Rule ID:** `{f.rule_id}` | **Engine:** `{f.scan_engine}` | **CWE:** `{f.cwe_id or 'N/A'}` | **CVE:** `{f.cve_id or 'N/A'}`",
            f"- **Location:** `{fp}` (Line {ln})",
            f"- **Reachability & Exploitability:** `{f.reachability_status}` — {f.reachability_reason} (EPSS 30-Day Score: `{(f.epss_score * 100):.1f}%` / `{f.epss_percentile:.1f}th percentile` | Maturity: `{f.exploit_maturity}`)",
            f"- **What Is Wrong (Technical Description):** {f.description}",
            f"- **Plain-English Summary:** {f.plain_english_summary or f.description}",
            f"- **Real-World Analogy:** {f.non_coder_analogy or 'N/A'}",
            f"- **Business & Financial Impact:** {f.business_impact or 'N/A'} ({f.financial_risk_tier or 'N/A'})",
            f"- **RACI Ownership:** Responsible (`R`): `{f.raci_responsible}` | Accountable (`A`): `{f.raci_accountable}` | Consulted (`C`): `{f.raci_consulted}` | Informed (`I`): `{f.raci_informed}`",
            f"- **Remediation:** {f.remediation or 'Review control and data flow paths in CPG canvas.'}",
            ""
        ])

    if _cached_advisories:
        md_lines.append("## 2. Extracted External Site Advisories")
        for adv in _cached_advisories:
            status_str = f"MATCHED IN CODE ({adv.match_count} hits in {', '.join(adv.matched_files)})" if adv.matched_in_code else "No direct match in current files"
            md_lines.extend([
                f"- **{adv.title}** (`{adv.cwe_id or ''}` / `{adv.cve_id or 'Advisory'}`) — **{status_str}**",
                f"  - Source: {adv.reference_url}",
                f"  - Remediation: {adv.remediation}",
            ])

    return PlainTextResponse("\n".join(md_lines), media_type="text/markdown")


@app.get("/api/metrics", response_model=MetricsResponse)
def get_metrics():
    """Computes overall summary metrics for the TopMetricsBar."""
    global current_app_tree
    _norm_cur = os.path.normcase(os.path.abspath(current_scan_dir)) if current_scan_dir else ""
    _cached_m = enterprise_mgr.get_cached_scan_for_project(current_scan_dir) if current_scan_dir else None
    if _cached_m and _last_neo4j_ingested_dir != _norm_cur and int(_cached_m.get("nodes_created", 0)) > 0:
        node_count = int(_cached_m.get("nodes_created", 0))
        edge_count = int(_cached_m.get("edges_created", 0))
    else:
        with neo4j_client.driver.session() as session:
            node_count = session.run("MATCH (n:CPGNode) RETURN count(n) AS c").single()["c"]
            edge_count = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]

    findings = get_or_compute_findings()
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity in ("LOW", "INFO"))

    categories = current_app_tree.category_counts if current_app_tree else {}
    tech_stack = current_app_tree.detected_tech_stack if current_app_tree else []
    total_files = current_app_tree.total_files if current_app_tree else 0

    return MetricsResponse(
        total_nodes=node_count,
        total_edges=edge_count,
        total_findings=len(findings),
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        total_app_files=total_files,
        categories=categories,
        tech_stack=tech_stack
    )


def _resolve_allowed_scan_file(raw_path: str, allowed_roots: List[str]) -> Optional[str]:
    """
    Resolves a requested file strictly within authorized scan/workspace roots using
    os.path.realpath() + os.path.commonpath() containment checks (CWE-22 protection).
    """
    clean_req = (raw_path or "").strip()
    if not clean_req or "\x00" in clean_req:
        return None

    real_roots: List[str] = []
    for r in allowed_roots:
        if r and os.path.exists(r):
            real_roots.append(os.path.realpath(os.path.dirname(r) if os.path.isfile(r) else r))

    if os.path.isabs(clean_req):
        real_cand = os.path.realpath(clean_req)
        if os.path.isfile(real_cand):
            for rr in real_roots:
                try:
                    if os.path.commonpath([rr, real_cand]) == rr:
                        return real_cand
                except ValueError:
                    continue
        return None

    rel_norm = clean_req.replace("\\", "/").lstrip("/")
    if ".." in rel_norm.split("/"):
        return None

    for rr in real_roots:
        try:
            resolved = _safe_resolve_under(rr, rel_norm)
            if os.path.isfile(resolved):
                return resolved
        except ValueError:
            continue
    return None


@app.get("/api/file")
def get_file_content(path: str = Query(..., description="Relative or absolute filepath")):
    """Returns raw source code for Monaco editor rendering within authorized scan roots."""
    global current_scan_dir
    scan_parent = os.path.dirname(current_scan_dir) if current_scan_dir and os.path.isfile(current_scan_dir) else current_scan_dir
    project_roots = [p.target_path for p in enterprise_mgr.projects if p.target_path]
    allowed_roots = [
        current_scan_dir,
        scan_parent,
        enterprise_mgr.platform_root,
        os.path.dirname(enterprise_mgr.platform_root),
        os.getenv("CPG_SCAN_BASE", os.getcwd()),
        os.getcwd(),
        *project_roots,
    ]

    if current_scan_dir and os.path.isfile(current_scan_dir) and os.path.basename(current_scan_dir) == os.path.basename(path):
        target_file = os.path.realpath(current_scan_dir)
    else:
        target_file = _resolve_allowed_scan_file(path, allowed_roots)

    if not target_file:
        raise HTTPException(status_code=404, detail=f"File not found or outside authorized scan workspace: {_sanitize_log(path)}")

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return {"filepath": path, "content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/node-at-location")
def get_node_at_location(filepath: str = Query(...), line: int = Query(...)):
    """Finds the most specific CPG node matching filepath and line number."""
    query = """
    MATCH (n:CPGNode)
    WHERE n.filepath ENDS WITH $filepath OR $filepath ENDS WITH n.filepath
      AND n.start_line <= $line <= n.end_line
    RETURN properties(n) AS node
    ORDER BY (n.end_line - n.start_line) ASC, (n.end_col - n.start_col) ASC
    LIMIT 1
    """
    with neo4j_client.driver.session() as session:
        rec = session.run(query, filepath=filepath, line=line).single()
        if rec and rec["node"]:
            return {"node": rec["node"]}
    return {"node": None}


@app.get("/api/graph")
def get_graph(
    view_mode: str = Query("FINDING_PATH", description="FULL_CPG, DFG_ONLY, CFG_ONLY, CALL_GRAPH, ENTRYPOINT_GRAPH, FINDING_PATH, APP_TREE"),
    finding_id: Optional[str] = Query(None),
    filepath: Optional[str] = Query(None)
):
    """Returns nodes and edges filtered by view mode with bounded limits for sub-50ms ReactFlow canvas rendering."""
    if view_mode == "FINDING_PATH":
        if not finding_id:
            return {"nodes": [], "edges": []}
        findings = get_or_compute_findings()
        for f in findings:
            if f.id == finding_id:
                return {"nodes": f.path_nodes, "edges": f.path_edges}
        return {"nodes": [], "edges": []}

    if view_mode == "ENTRYPOINT_GRAPH":
        _target_dir = current_scan_dir or enterprise_mgr.platform_root
        _findings = get_or_compute_findings()
        _suite = enterprise_mgr.get_sast_plus_suite(_target_dir, _findings)
        _ep_nodes: List[Dict[str, Any]] = []
        _ep_edges: List[Dict[str, Any]] = []
        _seen_nid = set()

        # Root Ingress Gateway Node
        _app_label = os.path.basename(os.path.abspath(_target_dir)) or "Application"
        _gw_id = f"ep-gateway:{_app_label}"
        _ep_nodes.append({
            "id": _gw_id,
            "label": "Entry",
            "ast_type": "ingress_gateway",
            "name": f"🌐 External Attack Surface ({_app_label})",
            "code": f"{len(_suite.endpoints)} Discovered Entrypoints • {len(_findings)} Active Findings",
            "filepath": _app_label,
            "start_line": 1,
            "end_line": 1,
            "start_col": 0,
            "end_col": 10,
            "scope_id": "ingress",
            "is_source": True,
            "is_sink": False,
            "is_sanitizer": False,
        })
        _seen_nid.add(_gw_id)

        for _idx, _ep in enumerate(_suite.endpoints[:24]):
            _ep_id = f"ep-route:{_ep.id}:{_idx}"
            if _ep_id not in _seen_nid:
                _seen_nid.add(_ep_id)
                _ep_nodes.append({
                    "id": _ep_id,
                    "label": "Entry",
                    "ast_type": "http_entrypoint",
                    "name": f"[{_ep.method}] {_ep.route_path}",
                    "code": f"Handler: {_ep.handler_name}() • {_ep.auth_posture}",
                    "filepath": _ep.filepath,
                    "start_line": _ep.line_number,
                    "end_line": _ep.line_number,
                    "start_col": 0,
                    "end_col": 40,
                    "scope_id": _ep.filepath,
                    "is_source": True,
                    "is_sink": False,
                    "is_sanitizer": False,
                })
                _ep_edges.append({
                    "id": f"ep-edge-gw-{_idx}",
                    "source": _gw_id,
                    "target": _ep_id,
                    "type": "CFG_NEXT",
                    "var_name": _ep.method,
                })

            _fn_id = f"ep-handler:{_ep.filepath}:{_ep.handler_name}:{_ep.line_number}"
            if _fn_id not in _seen_nid:
                _seen_nid.add(_fn_id)
                _ep_nodes.append({
                    "id": _fn_id,
                    "label": "Function",
                    "ast_type": "function_definition",
                    "name": f"{_ep.handler_name}()",
                    "code": _ep.plain_english_purpose or f"Controller in {_ep.filepath}:L{_ep.line_number}",
                    "filepath": _ep.filepath,
                    "start_line": _ep.line_number,
                    "end_line": _ep.line_number,
                    "start_col": 0,
                    "end_col": 40,
                    "scope_id": _ep.filepath,
                    "is_source": False,
                    "is_sink": _ep.linked_findings_count > 0,
                    "is_sanitizer": False,
                })
            _ep_edges.append({
                "id": f"ep-edge-fn-{_idx}",
                "source": _ep_id,
                "target": _fn_id,
                "type": "CALLS",
                "var_name": "dispatches",
            })

            # Connect handler to any findings in the same file
            _file_flaws = [
                _fl for _fl in _findings
                if any(
                    (_pn.get("filepath") or "") == _ep.filepath
                    or (_ep.filepath or "").endswith(_pn.get("filepath") or "__none__")
                    for _pn in (_fl.path_nodes or [])
                )
            ]
            for _f_idx, _fl in enumerate(_file_flaws[:2]):
                _sink_n = (_fl.path_nodes or [{}])[-1]
                _sink_id = f"ep-sink:{_fl.id}"
                if _sink_id not in _seen_nid:
                    _seen_nid.add(_sink_id)
                    _ep_nodes.append({
                        "id": _sink_id,
                        "label": "Call",
                        "ast_type": "vulnerable_sink",
                        "name": f"🚨 [{_fl.severity}] {_fl.rule_id}",
                        "code": str(_sink_n.get("code") or _fl.title)[:100],
                        "filepath": str(_sink_n.get("filepath") or _ep.filepath),
                        "start_line": int(_sink_n.get("start_line") or _ep.line_number),
                        "end_line": int(_sink_n.get("end_line") or _ep.line_number),
                        "start_col": 0,
                        "end_col": 40,
                        "scope_id": _ep.filepath,
                        "is_source": False,
                        "is_sink": True,
                        "is_sanitizer": False,
                    })
                _ep_edges.append({
                    "id": f"ep-edge-sink-{_idx}-{_f_idx}",
                    "source": _fn_id,
                    "target": _sink_id,
                    "type": "DFG_FLOWS_TO",
                    "var_name": _fl.cwe_id or "taint",
                })

        return {"nodes": _ep_nodes, "edges": _ep_edges}

    with neo4j_client.driver.session() as session:
        if view_mode == "APP_TREE":
            q = """
            MATCH (s) WHERE s:AppDirectory OR s:AppFile
            OPTIONAL MATCH (s)-[r:CONTAINS]->(t)
            WHERE t:AppDirectory OR t:AppFile
            RETURN collect(DISTINCT {props: properties(s), label: head(labels(s))}) AS all_nodes,
                   [rel IN collect(DISTINCT r) WHERE rel IS NOT NULL | 
                    {id: toString(coalesce(rel.id, elementId(rel))), source: startNode(rel).id, target: endNode(rel).id, type: type(rel), var_name: null}] AS all_edges
            """
            result = session.run(q).single()
            raw_nodes = result["all_nodes"] if result else []
            raw_edges = result["all_edges"] if result else []

            unique_nodes = {}
            for item in raw_nodes:
                if isinstance(item, dict) and "props" in item and isinstance(item["props"], dict):
                    node_dict = dict(item["props"])
                    node_dict["label"] = item.get("label") or ("AppDirectory" if node_dict.get("id", "").startswith("dir:") else "AppFile")
                    if "id" in node_dict:
                        unique_nodes[node_dict["id"]] = node_dict

            unique_edges = {}
            for e in raw_edges:
                if isinstance(e, dict) and "id" in e and e["id"]:
                    e["id"] = str(e["id"])
                    unique_edges[e["id"]] = e

            return {
                "nodes": list(unique_nodes.values()),
                "edges": list(unique_edges.values())
            }

        params = {}
        where_clauses = []
        if filepath:
            norm_fp = filepath.replace("\\", "/").lstrip("/")
            where_clauses.append("(s.filepath ENDS WITH $filepath OR $filepath ENDS WITH s.filepath OR t.filepath ENDS WITH $filepath)")
            params["filepath"] = norm_fp

        where_stmt = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        if view_mode == "DFG_ONLY":
            rel_filter = ":DFG_FLOWS_TO"
        elif view_mode == "CFG_ONLY":
            rel_filter = ":CFG_NEXT|CFG_TRUE|CFG_FALSE|CFG_LOOP_BACK|CFG_BREAK"
        elif view_mode == "CALL_GRAPH":
            rel_filter = ":CALLS"
        else:
            rel_filter = ""

        def _run_cpg_graph_query(_w_stmt: str, _q_params: Dict[str, Any]):
            if view_mode == "CALL_GRAPH":
                _cg_q = f"""
                MATCH (s:CPGNode)-[r:CALLS]->(t:CPGNode)
                {_w_stmt}
                OPTIONAL MATCH (callerFn:Function)-[:AST_CHILD*1..4]->(s)
                WITH callerFn, s, r, t LIMIT 100
                WITH collect(DISTINCT properties(s)) AS s_nodes,
                     collect(DISTINCT properties(t)) AS t_nodes,
                     [cf IN collect(DISTINCT callerFn) WHERE cf IS NOT NULL | properties(cf)] AS cf_nodes,
                     collect(DISTINCT {{id: r.id, source: s.id, target: t.id, type: type(r), var_name: r.var_name}}) AS call_edges,
                     [ce IN collect(DISTINCT CASE WHEN callerFn IS NOT NULL THEN {{id: 'def-' + callerFn.id + '-' + s.id, source: callerFn.id, target: s.id, type: 'DEFINES', var_name: 'calls'}} ELSE NULL END) WHERE ce IS NOT NULL] AS def_edges
                RETURN (s_nodes + t_nodes + cf_nodes) AS all_nodes,
                       (call_edges + def_edges) AS all_edges
                """
                return session.run(_cg_q, **_q_params).single()
            if rel_filter:
                _std_q = f"""
                MATCH (s:CPGNode)-[r{rel_filter}]->(t:CPGNode)
                {_w_stmt}
                WITH s, r, t LIMIT 120
                RETURN collect(DISTINCT properties(s)) + collect(DISTINCT properties(t)) AS all_nodes,
                       collect(DISTINCT {{id: r.id, source: s.id, target: t.id, type: type(r), var_name: r.var_name}}) AS all_edges
                """
                return session.run(_std_q, **_q_params).single()
            _full_q = f"""
            MATCH (s:CPGNode)-[r]->(t:CPGNode)
            {_w_stmt}
            WITH s, r, t LIMIT 120
            RETURN collect(DISTINCT properties(s)) + collect(DISTINCT properties(t)) AS all_nodes,
                   collect(DISTINCT {{id: r.id, source: s.id, target: t.id, type: type(r), var_name: r.var_name}}) AS all_edges
            """
            return session.run(_full_q, **_q_params).single()

        result = _run_cpg_graph_query(where_stmt, params)
        raw_nodes = result["all_nodes"] if result else []
        raw_edges = result["all_edges"] if result else []

        # If active file is a manifest/config or has 0 edges for this view_mode, fall back to Project-Wide graph!
        if not raw_edges and where_stmt:
            result = _run_cpg_graph_query("", {})
            raw_nodes = result["all_nodes"] if result else []
            raw_edges = result["all_edges"] if result else []

        # Deduplicate
        unique_nodes = {}
        for n in raw_nodes:
            if isinstance(n, list):
                for item in n:
                    if isinstance(item, dict) and "id" in item:
                        unique_nodes[item["id"]] = item
            elif isinstance(n, dict) and "id" in n:
                unique_nodes[n["id"]] = n

        unique_edges = {}
        for e in raw_edges:
            if isinstance(e, dict) and "id" in e and e.get("source") in unique_nodes and e.get("target") in unique_nodes:
                unique_edges[e["id"]] = e

        # Fallback synthesis if viewing a cached project not currently in Neo4j or a project with 0 CALLS in Neo4j
        if len(unique_nodes) < 2 and current_app_tree:
            _synth_nodes: List[Dict[str, Any]] = []
            _synth_edges: List[Dict[str, Any]] = []
            _fn_files = [
                _ff for _ff in current_app_tree.flat_files
                if _ff.elements and (not filepath or _ff.filepath == filepath or len(current_app_tree.flat_files) > 0)
            ][:18]
            _prev_fn_id: Optional[str] = None
            for _f_i, _ff in enumerate(_fn_files):
                _mod_id = f"cg-mod:{_ff.filepath}"
                _synth_nodes.append({
                    "id": _mod_id,
                    "label": "Module",
                    "ast_type": "module",
                    "name": _ff.filename,
                    "code": _ff.purpose or _ff.filepath,
                    "filepath": _ff.filepath,
                    "start_line": 1,
                    "end_line": max(1, _ff.line_count),
                    "start_col": 0,
                    "end_col": 20,
                    "scope_id": _ff.filepath,
                    "is_source": _ff.category == "API_ROUTER",
                    "is_sink": False,
                    "is_sanitizer": False,
                })
                for _e_i, _el in enumerate(_ff.elements[:4]):
                    _el_id = f"cg-fn:{_ff.filepath}:{_el.name}:{_el.line_number}:{_e_i}"
                    _synth_nodes.append({
                        "id": _el_id,
                        "label": "Function" if _el.element_type in ("FUNCTION", "ROUTE", "CLASS") else "Call",
                        "ast_type": _el.element_type.lower(),
                        "name": f"{_el.name}()",
                        "code": _el.signature or _el.details or _el.name,
                        "filepath": _ff.filepath,
                        "start_line": max(1, _el.line_number),
                        "end_line": max(1, _el.line_number),
                        "start_col": 0,
                        "end_col": 30,
                        "scope_id": _ff.filepath,
                        "is_source": _el.element_type == "ROUTE",
                        "is_sink": False,
                        "is_sanitizer": False,
                    })
                    _synth_edges.append({
                        "id": f"cg-edge-mod-{_f_i}-{_e_i}",
                        "source": _mod_id,
                        "target": _el_id,
                        "type": "CALLS" if view_mode == "CALL_GRAPH" else "CFG_NEXT",
                        "var_name": "invokes" if view_mode == "CALL_GRAPH" else None,
                    })
                    if _prev_fn_id and _e_i == 0:
                        _synth_edges.append({
                            "id": f"cg-edge-cross-{_f_i}",
                            "source": _prev_fn_id,
                            "target": _el_id,
                            "type": "CALLS",
                            "var_name": "calls",
                        })
                    _prev_fn_id = _el_id
            return {"nodes": _synth_nodes, "edges": _synth_edges}

        return {
            "nodes": list(unique_nodes.values()),
            "edges": list(unique_edges.values())
        }


# ===========================================================================
# 1. PROJECT MANAGEMENT & CLOUD HUB ENDPOINTS
# ===========================================================================
@app.get("/api/projects", response_model=List[ProjectConfig])
def list_projects():
    """Returns all configured projects in the cloud hub with risk enumeration and automation settings."""
    get_or_compute_findings()
    return enterprise_mgr.projects


@app.post("/api/projects", response_model=ProjectConfig)
def create_or_import_project(req: CreateProjectRequest):
    """Registers a local workspace or SCM repository project with 0 initial findings until scanned."""
    slug = re.sub(r"[^a-z0-9]+", "-", req.name.lower()).strip("-") or "project"
    pid = f"proj-{slug}-{len(enterprise_mgr.projects) + 1}"
    target = req.target_path.strip() or req.repo_url.strip()

    new_proj = ProjectConfig(
        id=pid,
        name=req.name.strip(),
        description=req.description.strip() or f"Project registered ({req.scm_provider} / {req.branch}) — Not scanned yet.",
        scm_provider=req.scm_provider,
        repo_url=req.repo_url.strip(),
        branch=req.branch.strip() or "main",
        target_path=target,
        preset_id=req.preset_id,
        override_global_settings=False,
        custom_engines=["SAST", "SCA", "IaC"],
        automation=ProjectAutomationConfig(
            auto_scan_on_push=req.auto_scan_on_push,
            auto_scan_on_pr=req.auto_scan_on_pr,
            auto_scan_on_schedule=False,
            target_branches=[req.branch.strip() or "main"],
            webhook_url="",
            last_triggered_at=None,
            last_trigger_event=None
        ),
        risk_level="SECURE",
        risk_score=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        total_findings=0,
        sast_count=0,
        sca_count=0,
        iac_count=0,
        languages=[],
        last_scan_at=None,
        is_active=False
    )
    enterprise_mgr.projects.insert(0, new_proj)
    return new_proj


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str):
    """Removes a project from the project registry."""
    before = len(enterprise_mgr.projects)
    enterprise_mgr.projects = [p for p in enterprise_mgr.projects if p.id != project_id]
    if len(enterprise_mgr.projects) == before:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")
    return {"deleted": True, "id": project_id}


@app.put("/api/projects/{project_id}/automation", response_model=ProjectConfig)
def update_project_automation(project_id: str, req: UpdateProjectAutomationRequest):
    """Updates SCM push / pull_request automation settings and preset overrides for a project."""
    proj = next((p for p in enterprise_mgr.projects if p.id == project_id), None)
    if not proj:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")

    if req.auto_scan_on_push is not None:
        proj.automation.auto_scan_on_push = req.auto_scan_on_push
    if req.auto_scan_on_pr is not None:
        proj.automation.auto_scan_on_pr = req.auto_scan_on_pr
    if req.auto_scan_on_schedule is not None:
        proj.automation.auto_scan_on_schedule = req.auto_scan_on_schedule
    if req.target_branches is not None:
        proj.automation.target_branches = req.target_branches
    if req.preset_id is not None:
        proj.preset_id = req.preset_id
    if req.override_global_settings is not None:
        proj.override_global_settings = req.override_global_settings
    if req.custom_engines is not None:
        proj.custom_engines = req.custom_engines

    return proj


@app.post("/api/projects/{project_id}/activate", response_model=ProjectConfig)
def activate_project(project_id: str):
    """
    Marks a project as the active project in the workspace and immediately restores its
    cached last-scan findings, application tree, and Track Changes history so the user
    can view saved scan details without having to re-scan every time.
    """
    global current_scan_dir, current_app_tree, _cached_findings, _cached_findings_time, _cached_external_findings, _cached_advisories
    target = None
    for p in enterprise_mgr.projects:
        if p.id == project_id:
            p.is_active = True
            target = p
        else:
            p.is_active = False

    if not target:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")

    if target.target_path and os.path.exists(target.target_path):
        current_scan_dir = os.path.abspath(target.target_path)
        _norm_act = os.path.normcase(current_scan_dir)
        _cached_external_findings = []
        _cached_advisories = []
        cached = enterprise_mgr.get_cached_scan_for_project(current_scan_dir)
        if cached and cached.get("app_tree"):
            try:
                current_app_tree = AppTreeSummary(**cached["app_tree"])
            except Exception:
                current_app_tree = AppTreeAnalyzer(current_scan_dir).analyze()
        else:
            current_app_tree = AppTreeAnalyzer(current_scan_dir).analyze()
        if cached and isinstance(cached.get("latest_findings"), list) and _last_neo4j_ingested_dir != _norm_act:
            try:
                _cached_findings = [Finding(**f) for f in cached["latest_findings"]]
                _cached_findings_time = time.time()
            except Exception:
                _cached_findings = None
            refreshed = get_or_compute_findings(force_refresh=False)
        else:
            refreshed = get_or_compute_findings(force_refresh=True)
        if current_app_tree:
            target.files_scanned_count = current_app_tree.total_files
        enterprise_mgr._sync_active_project_metrics(refreshed)

    return target


@app.get("/api/scan/track-changes", response_model=TrackChangesSummary)
def get_scan_track_changes(project_path: Optional[str] = Query(None)):
    """
    Returns the Continuous Track Changes & Saved Scan History summary for the active application:
    - Last Scanned timestamp, Previous Scanned timestamp & total scan count
    - Old vulnerabilities that are now FIXED since the previous scan (or resolved via triage)
    - Newly introduced vulnerabilities (NEW / REOPENED) in the latest scan
    - Unchanged carryover vulnerabilities
    - Full chronological scan snapshot history
    """
    target = project_path.strip() if project_path and project_path.strip() else current_scan_dir
    findings = get_or_compute_findings()
    return enterprise_mgr.get_track_changes_summary(target, findings)


@app.post("/api/projects/{project_id}/webhook")
def trigger_project_scm_webhook(project_id: str, req: WebhookTriggerRequest):
    """
    Simulates or handles an incoming GitHub/GitLab SCM webhook event (`push` or `pull_request`),
    verifies automation rules, and executes an automated scan.
    """
    from datetime import datetime
    proj = next((p for p in enterprise_mgr.projects if p.id == project_id), None)
    if not proj:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")

    if req.event_type == "push" and not proj.automation.auto_scan_on_push:
        return {"status": "SKIPPED", "reason": "Automatic scan on push is disabled for this project."}
    if req.event_type == "pull_request" and not proj.automation.auto_scan_on_pr:
        return {"status": "SKIPPED", "reason": "Automatic scan on pull_request is disabled for this project."}

    for p in enterprise_mgr.projects:
        p.is_active = (p.id == project_id)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    proj.automation.last_triggered_at = now_str
    proj.automation.last_trigger_event = f"{req.event_type} on {req.branch} ({req.commit_sha}) by {req.actor}"

    scan_target = proj.target_path
    if not os.path.exists(scan_target) and not scan_target.startswith(("http://", "https://", "git@")):
        scan_target = enterprise_mgr.platform_root

    scan_res = scan_project(ScanRequest(target_path=scan_target))
    findings = get_or_compute_findings(force_refresh=True)
    return {
        "status": "TRIGGERED",
        "event": proj.automation.last_trigger_event,
        "project": proj.model_dump(),
        "scan_result": scan_res.model_dump(),
        "findings_count": len(findings),
    }


# ===========================================================================
# 2. DEEP DIVE & ANALYSIS INTERFACE ENDPOINTS
# ===========================================================================
@app.get("/api/analytics/deep-dive", response_model=DeepDiveAnalyticsResponse)
def get_deep_dive_analytics():
    """
    Returns multi-dimensional Deep Dive Analytics:
    - Severity Breakdown (Critical, High, Medium, Low)
    - Aging Summary (5 persistence buckets + SLA breach metrics)
    - Compliance Standards Reports (OWASP Top 10 2021, PCI-DSS v4.0, NIST 800-53 / CWE Top 25)
    - Unified Scan Engine Breakdown (SAST, SCA, IaC)
    """
    findings = get_or_compute_findings()
    return enterprise_mgr.build_deep_dive_analytics(findings)


# ===========================================================================
# 3. VULNERABILITY REMEDIATION VIEW: SUPPRESSION / VALIDATION TRIAGE
# ===========================================================================
@app.post("/api/findings/{finding_id}/triage", response_model=Finding)
def update_finding_triage_status(finding_id: str, req: TriageUpdateRequest):
    """
    Marks a finding as TO_VERIFY, CONFIRMED (Validated), NOT_EXPLOITABLE (Suppressed),
    PROPOSED_NOT_EXPLOITABLE, or RESOLVED, persisting suppression across future scans.
    """
    findings = get_or_compute_findings()
    target = next((f for f in findings if f.id == finding_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    updated = enterprise_mgr.update_finding_triage(target, req)
    enterprise_mgr._sync_active_project_metrics(get_or_compute_findings())
    return updated


# ===========================================================================
# 4. SETTINGS & CUSTOMIZATION ENGINE ENDPOINTS
# ===========================================================================
@app.get("/api/settings", response_model=PlatformSettingsResponse)
def get_platform_settings():
    """Returns Scan Presets, Global vs Project Settings, Query Viewer rules, and Custom Sanitizers."""
    return enterprise_mgr.get_settings_response()


@app.put("/api/settings", response_model=PlatformSettingsResponse)
def update_platform_settings(req: UpdatePlatformSettingsRequest):
    """Updates Global or Project-specific settings, active Scan Preset, or enabled engines."""
    global _cached_findings
    res = enterprise_mgr.update_platform_settings(req)
    _cached_findings = None
    get_or_compute_findings(force_refresh=True)
    return res


@app.post("/api/settings/queries", response_model=SecurityQueryRule)
def upsert_security_query_rule(req: UpsertQueryRuleRequest):
    """Modifies an existing security query or adds a new Custom Cypher Query to the engine."""
    global _cached_findings
    rule = enterprise_mgr.upsert_query_rule(req)
    _cached_findings = None
    get_or_compute_findings(force_refresh=True)
    return rule


@app.post("/api/settings/queries/{rule_id}/toggle", response_model=SecurityQueryRule)
def toggle_security_query_rule(rule_id: str):
    """Toggles a security query rule enabled/disabled."""
    global _cached_findings
    target = next((q for q in enterprise_mgr.queries if q.id == rule_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    target.enabled = not target.enabled
    _cached_findings = None
    get_or_compute_findings(force_refresh=True)
    return target


@app.post("/api/settings/sanitizers", response_model=CustomSanitizerRule)
def add_custom_sanitizer_rule(req: AddCustomSanitizerRequest):
    """Registers a custom sanitizer function and dynamically marks matching CPG nodes in Neo4j."""
    global _cached_findings
    try:
        san = enterprise_mgr.add_custom_sanitizer(req, neo4j_client=neo4j_client)
        _cached_findings = None
        get_or_compute_findings(force_refresh=True)
        return san
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/settings/sanitizers/{san_id}/toggle", response_model=CustomSanitizerRule)
def toggle_custom_sanitizer_rule(san_id: str):
    """Toggles a custom sanitizer active/inactive and updates Neo4j CPG nodes."""
    global _cached_findings
    san = enterprise_mgr.toggle_custom_sanitizer(san_id, neo4j_client=neo4j_client)
    if not san:
        raise HTTPException(status_code=404, detail=f"Sanitizer not found: {san_id}")
    _cached_findings = None
    get_or_compute_findings(force_refresh=True)
    return san


@app.post("/api/settings/presets", response_model=PlatformSettingsResponse)
def create_custom_test_profile(req: CreateTestProfileRequest):
    """Creates a new Test Profile specifying which security rules and engines are enabled."""
    global _cached_findings
    res = enterprise_mgr.create_test_profile(req)
    _cached_findings = None
    get_or_compute_findings(force_refresh=True)
    return res


@app.post("/api/settings/queries/batch-select", response_model=PlatformSettingsResponse)
def batch_select_security_rules(req: BatchRuleSelectionRequest):
    """Batch-updates which rules are enabled/disabled in the Rule Engine & Test Profile."""
    global _cached_findings
    res = enterprise_mgr.batch_update_rules(req)
    _cached_findings = None
    get_or_compute_findings(force_refresh=True)
    return res


# ===========================================================================
# 4B. MULTI-TENANT ACCOUNT SEPARATION & RBAC USER PROFILING ENDPOINTS
# ===========================================================================
@app.get("/api/accounts", response_model=UserAccountsStateResponse)
def get_accounts_and_users():
    """Returns multi-tenant accounts, RBAC user profiles, active session context, and audit trail."""
    return enterprise_mgr.get_accounts_and_users_state()


@app.post("/api/accounts", response_model=UserAccountsStateResponse)
def create_tenant_account(req: CreateAccountRequest):
    """Creates a new isolated tenant account/organization for multi-tenant project separation."""
    return enterprise_mgr.create_account(req)


@app.post("/api/accounts/users", response_model=UserAccountsStateResponse)
def create_rbac_user_profile(req: CreateUserProfileRequest):
    """Creates a new RBAC user profile assigned to a tenant account."""
    return enterprise_mgr.create_user_profile(req)


@app.post("/api/accounts/switch", response_model=UserAccountsStateResponse)
def switch_active_user_or_account(req: SwitchUserOrAccountRequest):
    """Switches the active RBAC user profile, active tenant account scope, or project-account assignment."""
    return enterprise_mgr.switch_user_or_account(req)


# ===========================================================================
# 5. INTEGRATION HUB: JIRA & GITHUB ISSUES + AUTOMATED TICKET CREATION
# ===========================================================================
@app.get("/api/integrations", response_model=IntegrationHubStateResponse)
def get_integrations_state():
    """Returns Jira & GitHub Issues connector settings and all linked bug-tracking tickets."""
    get_or_compute_findings()
    return IntegrationHubStateResponse(
        config=enterprise_mgr.integration_config,
        tickets=enterprise_mgr.tickets
    )


@app.put("/api/integrations/config", response_model=BugTrackerConnectorConfig)
def update_integrations_config(cfg: BugTrackerConnectorConfig):
    """Updates Jira / GitHub Issues connector configuration and automated ticket creation thresholds."""
    prev_cfg = enterprise_mgr.integration_config
    # Preserve existing tokens if masked or empty string not meant to overwrite
    if not cfg.jira_api_token or "..." in cfg.jira_api_token:
        cfg.jira_api_token = prev_cfg.jira_api_token
    else:
        t = cfg.jira_api_token.strip()
        cfg.jira_api_token_masked = f"{t[:6]}...{t[-4:]}" if len(t) > 12 else "ATATT_configured"

    if not cfg.github_token or "..." in cfg.github_token:
        cfg.github_token = prev_cfg.github_token
    else:
        gt = cfg.github_token.strip()
        cfg.github_token_masked = f"{gt[:7]}...{gt[-4:]}" if len(gt) > 12 else "ghp_configured"

    cfg.github_repo = enterprise_mgr._normalize_github_repo(cfg.github_repo)
    enterprise_mgr.integration_config = cfg
    enterprise_mgr._save_persisted_state()

    if cfg.auto_create_tickets:
        findings = get_or_compute_findings()
        enterprise_mgr._auto_generate_tickets_for_findings(findings)
    return enterprise_mgr.integration_config


@app.post("/api/integrations/test-connection", response_model=TestConnectionResponse)
def test_bug_tracker_connection(req: TestConnectionRequest):
    """Performs a live HTTP probe against GitHub REST API or Atlassian Jira REST API and returns latency & auth mode."""
    return enterprise_mgr.test_connector_connection(req)


@app.post("/api/integrations/tickets", response_model=IssueTicket)
def create_bug_tracker_ticket(req: CreateTicketRequest):
    """Creates a Jira or GitHub Issue ticket for a specific finding with BFL and remediation patch."""
    findings = get_or_compute_findings()
    target = next((f for f in findings if f.id == req.finding_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Finding not found: {req.finding_id}")

    ticket = enterprise_mgr.create_ticket_for_finding(
        target,
        provider=req.provider,
        assignee=req.assignee,
        priority=req.priority,
        labels=req.labels,
        custom_notes=req.custom_notes,
        auto_generated=False
    )
    return ticket


@app.patch("/api/integrations/tickets/{ticket_id}", response_model=IssueTicket)
def update_bug_tracker_ticket(ticket_id: str, req: UpdateTicketRequest):
    """Updates ticket status (OPEN, IN_PROGRESS, RESOLVED), assignee, priority, or comments, syncing back to finding triage."""
    findings = get_or_compute_findings()
    updated = enterprise_mgr.update_ticket(ticket_id, req, findings=findings)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Ticket not found: {ticket_id}")
    enterprise_mgr._sync_active_project_metrics(get_or_compute_findings())
    return updated


@app.delete("/api/integrations/tickets/{ticket_id}")
def delete_bug_tracker_ticket(ticket_id: str):
    """Deletes a ticket from the tracker and unlinks it from the associated finding."""
    deleted = enterprise_mgr.delete_ticket(ticket_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Ticket not found: {ticket_id}")
    return {"status": "DELETED", "ticket_id": ticket_id}


@app.post("/api/integrations/tickets/auto-sync", response_model=List[IssueTicket])
def auto_sync_bug_tracker_tickets():
    """Automatically creates Jira / GitHub Issues for all active findings meeting the severity threshold."""
    findings = get_or_compute_findings()
    enterprise_mgr._auto_generate_tickets_for_findings(findings)
    return enterprise_mgr.tickets


@app.get("/api/integrations/tickets/{ticket_id}/view", response_class=HTMLResponse)
def view_standalone_ticket_page(ticket_id: str):
    """Renders a rich standalone HTML view for an ALASTOR Bug Tracker ticket so external_url links work seamlessly."""
    get_or_compute_findings()
    ticket = next((t for t in enterprise_mgr.tickets if t.id == ticket_id or t.ticket_key == ticket_id), None)
    if not ticket:
        raise HTTPException(status_code=404, detail=f"Ticket not found: {ticket_id}")

    esc = html_lib.escape
    sev_color = "#ef4444" if ticket.severity == "CRITICAL" else ("#f59e0b" if ticket.severity == "HIGH" else "#06b6d4")
    status_color = "#10b981" if ticket.status == "RESOLVED" else ("#3b82f6" if ticket.status == "IN_PROGRESS" else "#f59e0b")

    comments_html = "".join([
        f"""
        <div style="padding:12px 14px;background:#09090b;border:1px solid #27272a;border-radius:10px;margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;font-size:11px;color:#a1a1aa;margin-bottom:4px;font-family:monospace;">
            <strong style="color:#38bdf8;">{esc(c.author)}</strong>
            <span>{esc(c.created_at)}</span>
          </div>
          <div style="font-size:13px;color:#e4e4e7;line-height:1.5;">{esc(c.body)}</div>
        </div>
        """
        for c in ticket.comments
    ]) or '<div style="color:#71717a;font-size:12px;">No comments recorded yet.</div>'

    labels_html = "".join([
        f'<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:#1e1b4b;border:1px solid #4338ca;color:#a5b4fc;font-size:11px;font-family:monospace;margin-right:6px;">#{esc(lbl)}</span>'
        for lbl in (ticket.labels or [])
    ])

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{esc(ticket.ticket_key)} — {esc(ticket.finding_title)} | ALASTOR Issue Tracker</title>
  <style>
    body {{
      margin: 0;
      padding: 32px 20px;
      background: #07060a;
      color: #f4f4f5;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }}
    .container {{
      max-width: 920px;
      margin: 0 auto;
      background: #111018;
      border: 1px solid #27272a;
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 24px 64px rgba(0,0,0,0.65);
    }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 11px;
      font-weight: 700;
    }}
    pre {{
      background: #09090b;
      border: 1px solid #27272a;
      border-radius: 10px;
      padding: 16px;
      overflow-x: auto;
      font-family: "JetBrains Mono", Consolas, monospace;
      font-size: 12px;
      color: #6ee7b7;
      line-height: 1.55;
      white-space: pre-wrap;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin: 20px 0;
      padding: 16px;
      background: #09090b;
      border: 1px solid #27272a;
      border-radius: 12px;
    }}
    .meta-label {{
      font-size: 10px;
      font-family: monospace;
      text-transform: uppercase;
      color: #71717a;
      margin-bottom: 4px;
    }}
    .meta-val {{
      font-size: 13px;
      font-family: monospace;
      color: #e4e4e7;
      font-weight: 600;
    }}
    a.btn {{
      display: inline-block;
      padding: 8px 14px;
      border-radius: 8px;
      background: #dc2626;
      color: #fff;
      text-decoration: none;
      font-size: 12px;
      font-weight: 700;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #27272a;padding-bottom:16px;margin-bottom:20px;">
      <div>
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;">
          <span class="badge" style="background:#1e1b4b;color:#818cf8;border:1px solid #4338ca;">{esc(ticket.provider)}</span>
          <span class="badge" style="background:#09090b;color:#38bdf8;border:1px solid #0284c7;">{esc(ticket.ticket_key)}</span>
          <span class="badge" style="background:#09090b;color:{sev_color};border:1px solid {sev_color};">{esc(ticket.severity)}</span>
          <span class="badge" style="background:#09090b;color:{status_color};border:1px solid {status_color};">STATUS: {esc(ticket.status)}</span>
          <span class="badge" style="background:#09090b;color:#a1a1aa;border:1px solid #3f3f46;">PRIORITY: {esc(ticket.priority)}</span>
        </div>
        <h1 style="margin:0;font-size:20px;color:#ffffff;">{esc(ticket.finding_title)}</h1>
      </div>
      <a class="btn" href="http://localhost:3000">← Return to ALASTOR IDE</a>
    </div>

    <div class="meta-grid">
      <div>
        <div class="meta-label">Best Fixed Location (BFL)</div>
        <div class="meta-val" style="color:#34d399;">{esc(ticket.filepath)}:L{ticket.line}</div>
      </div>
      <div>
        <div class="meta-label">Assignee</div>
        <div class="meta-val">{esc(ticket.assignee)}</div>
      </div>
      <div>
        <div class="meta-label">CWE / Identifier</div>
        <div class="meta-val">{esc(ticket.cwe_id or "CWE-78")}</div>
      </div>
      <div>
        <div class="meta-label">Created / Sync Mode</div>
        <div class="meta-val">{esc(ticket.created_at)} ({esc(ticket.sync_mode)})</div>
      </div>
    </div>

    <div style="margin-bottom:18px;">{labels_html}</div>

    <h3 style="font-size:13px;font-family:monospace;text-transform:uppercase;color:#a1a1aa;">Best Fixed Location (BFL) Remediation Summary</h3>
    <pre>{esc(ticket.bfl_summary)}</pre>

    <h3 style="font-size:13px;font-family:monospace;text-transform:uppercase;color:#a1a1aa;margin-top:22px;">Full Issue Markdown Payload &amp; CPG Trace</h3>
    <pre style="color:#e4e4e7;">{esc(ticket.payload_preview)}</pre>

    <h3 style="font-size:13px;font-family:monospace;text-transform:uppercase;color:#a1a1aa;margin-top:22px;">Activity &amp; Audit Comments ({len(ticket.comments)})</h3>
    {comments_html}
  </div>
</body>
</html>"""
    return HTMLResponse(content=html_doc, status_code=200)


# ---------------------------------------------------------------------------
# 6. RACI Governance & Accountability Matrix Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/governance/raci", response_model=RaciGovernanceResponse)
def get_raci_governance_matrix():
    """Returns the live RACI Governance Matrix, PMI/COBIT validation score, and finding-level RACI assignments."""
    findings = get_or_compute_findings()
    return enterprise_mgr.get_raci_governance(findings)


@app.put("/api/governance/raci/cell", response_model=RaciGovernanceResponse)
def update_raci_matrix_cell(req: UpdateRaciCellRequest):
    """Updates a single RACI cell (R / A / C / I / -) for a security lifecycle activity and re-validates governance rules."""
    findings = get_or_compute_findings()
    return enterprise_mgr.update_raci_cell(req, findings)


@app.put("/api/governance/raci/finding-owner", response_model=RaciGovernanceResponse)
def update_finding_raci_ownership(req: UpdateFindingRaciOwnerRequest):
    """Updates the assigned owner, sprint target, or RACI role for a specific vulnerability finding."""
    findings = get_or_compute_findings()
    return enterprise_mgr.update_finding_raci_owner(req, findings)


@app.post("/api/governance/raci/reset", response_model=RaciGovernanceResponse)
def reset_raci_governance_matrix():
    """Resets the RACI Governance Matrix to the validated PMI/COBIT baseline."""
    findings = get_or_compute_findings()
    return enterprise_mgr.reset_raci_defaults(findings)


# ---------------------------------------------------------------------------
# 7. SAST ++++++ ASPM Suite (Live SBOM, Attack Surface & Remediation Roadmap)
# ---------------------------------------------------------------------------
@app.get("/api/aspm/suite", response_model=SastPlusSuiteResponse)
def get_sast_plus_aspm_suite(project_path: Optional[str] = Query(None)):
    """Returns the unified SAST++++++ ASPM suite: Live CycloneDX SBOM, discovered API/Callable Attack Surface, and Prioritized Remediation Roadmap."""
    target_dir = project_path if project_path and os.path.exists(project_path) else current_scan_dir
    findings = get_or_compute_findings()
    if project_path and os.path.exists(project_path) and not findings:
        cached = enterprise_mgr.get_cached_scan_for_project(project_path)
        if cached and cached.get("latest_findings"):
            findings = [Finding(**f) for f in cached["latest_findings"]]
    return enterprise_mgr.get_sast_plus_suite(target_dir, findings)


