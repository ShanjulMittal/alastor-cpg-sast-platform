"""
ALASTOR v5.0 Pillar 4 — SQLite WAL Stage Checkpoint Store, Host Provenance & GC.

Persists scan run metadata, stage-level SHA-256-verified payloads (for `--resume`),
host provenance fingerprints (for `remediate --mode fix`), fleet batch run summaries,
and retention garbage collection (`gc`) inside `<vault_dir>/checkpoints.db`.

Security & Reliability Invariants:
- 100% static parameterized `?` SQLite queries ONLY (zero SQL string interpolation).
- `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`
- `0o700` vault directory / `0o600` database file permissions (best-effort on Windows).
- Thread-safe via `threading.Lock()`.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from engine.hostile_repo_guard import (
    HostileRepoError,
    is_entry_link_or_junction,
    is_link_or_junction,
    safe_cleanup_workspace,
)
from models import (
    FleetRunListResponse,
    FleetRunResponse,
    GcReport,
    ScanRunCheckpointSummary,
    StageCheckpointItem,
)

_VALID_RUN_STATUSES = {"RUNNING", "COMPLETED", "FAILED", "PARTIAL"}
_VALID_STAGE_STATUSES = {"PENDING", "RUNNING", "COMPLETED", "FAILED", "SKIPPED"}


def _best_effort_chmod(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso_utc(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _measure_dir_bytes_no_follow(dir_path: str) -> int:
    total = 0
    try:
        with os.scandir(dir_path) as it:
            for entry in it:
                if is_entry_link_or_junction(entry):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    total += _measure_dir_bytes_no_follow(entry.path)
                else:
                    try:
                        total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
    except OSError:
        pass
    return total


class CheckpointStore:
    """SQLite WAL-backed checkpoint, provenance, fleet-run, and GC manager."""

    def __init__(self, vault_dir: str):
        if not isinstance(vault_dir, str) or not vault_dir.strip() or any(c in vault_dir for c in ("\r", "\n", "\x00")):
            raise ValueError("vault_dir must be a non-empty valid directory path")
        self.vault_dir = os.path.realpath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)
        _best_effort_chmod(self.vault_dir, 0o700)

        self.db_path = os.path.join(self.vault_dir, "checkpoints.db")
        self._lock = threading.Lock()
        self.host_fingerprint = hashlib.sha256(
            f"{socket.gethostname()}|{self.vault_dir}".encode("utf-8")
        ).hexdigest()[:32]

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._init_schema_unlocked()
        _best_effort_chmod(self.db_path, 0o600)

    def _init_schema_unlocked(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                run_id TEXT PRIMARY KEY,
                repo_path TEXT NOT NULL,
                commit_sha TEXT NOT NULL DEFAULT '',
                app_group TEXT NOT NULL DEFAULT 'default',
                host_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                options_json TEXT NOT NULL DEFAULT '{}',
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_repo_commit ON scan_runs (repo_path, commit_sha, updated_at)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_updated ON scan_runs (updated_at)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stage_checkpoints (
                run_id TEXT NOT NULL,
                stage_name TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT 'null',
                payload_sha256 TEXT NOT NULL DEFAULT '',
                duration_ms REAL NOT NULL DEFAULT 0.0,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL,
                PRIMARY KEY (run_id, stage_name),
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fleet_runs (
                fleet_run_id TEXT PRIMARY KEY,
                manifest_name TEXT NOT NULL,
                status TEXT NOT NULL,
                total_repos INTEGER NOT NULL DEFAULT 0,
                completed_repos INTEGER NOT NULL DEFAULT 0,
                failed_repos INTEGER NOT NULL DEFAULT 0,
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None  # type: ignore[assignment]

    def __enter__(self) -> "CheckpointStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _require_conn_unlocked(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("CheckpointStore connection is closed")
        return self._conn

    def _read_valid_stages_unlocked(self, run_id: str) -> List[StageCheckpointItem]:
        conn = self._require_conn_unlocked()
        rows = conn.execute(
            """
            SELECT stage_name, status, payload_json, payload_sha256, duration_ms, metadata_json, updated_at
            FROM stage_checkpoints
            WHERE run_id = ?
            ORDER BY rowid ASC
            """,
            (run_id,),
        ).fetchall()
        items: List[StageCheckpointItem] = []
        for row in rows:
            payload_json = row["payload_json"]
            actual_sha = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            if actual_sha != row["payload_sha256"]:
                continue
            try:
                json.loads(payload_json)
                meta = json.loads(row["metadata_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(meta, dict):
                meta = {}
            items.append(
                StageCheckpointItem(
                    stage_name=row["stage_name"],
                    status=row["status"],
                    payload_sha256=row["payload_sha256"],
                    duration_ms=float(row["duration_ms"]),
                    updated_at=row["updated_at"],
                    metadata=meta,
                )
            )
        return items

    def _build_run_summary_unlocked(self, row: sqlite3.Row) -> ScanRunCheckpointSummary:
        try:
            summary_obj = json.loads(row["summary_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            summary_obj = {}
        if not isinstance(summary_obj, dict):
            summary_obj = {}

        stages = self._read_valid_stages_unlocked(row["run_id"])
        return ScanRunCheckpointSummary(
            run_id=row["run_id"],
            repo_path=row["repo_path"],
            commit_sha=row["commit_sha"],
            app_group=row["app_group"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            host_provenance_valid=(row["host_fingerprint"] == self.host_fingerprint),
            stages=stages,
            summary=summary_obj,
        )

    def create_or_get_run(
        self,
        repo_path: str,
        commit_sha: str = "",
        app_group: str = "default",
        options: Optional[Dict[str, Any]] = None,
        run_id: Optional[str] = None,
        resume: bool = False,
    ) -> ScanRunCheckpointSummary:
        canonical_repo = os.path.realpath(repo_path)
        norm_repo = os.path.normcase(canonical_repo)
        commit_sha_clean = str(commit_sha or "")
        app_group_clean = str(app_group or "default")

        with self._lock:
            conn = self._require_conn_unlocked()
            if run_id is not None:
                existing = conn.execute(
                    "SELECT * FROM scan_runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if existing is not None:
                    if os.path.normcase(existing["repo_path"]) != norm_repo:
                        raise ValueError(
                            f"Run '{run_id}' belongs to repository '{existing['repo_path']}', not '{canonical_repo}'"
                        )
                    return self._build_run_summary_unlocked(existing)

            if resume and run_id is None:
                candidates = conn.execute(
                    """
                    SELECT * FROM scan_runs
                    WHERE commit_sha = ?
                    ORDER BY updated_at DESC, rowid DESC
                    """,
                    (commit_sha_clean,),
                ).fetchall()
                for row in candidates:
                    if os.path.normcase(row["repo_path"]) != norm_repo:
                        continue
                    if row["host_fingerprint"] != self.host_fingerprint:
                        continue
                    try:
                        opts = json.loads(row["options_json"] or "{}")
                        summ = json.loads(row["summary_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if not isinstance(opts, dict) or not isinstance(summ, dict):
                        continue
                    return self._build_run_summary_unlocked(row)

            new_run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
            now = _utc_now_iso()
            options_json = json.dumps(options or {}, sort_keys=True, default=str)
            conn.execute(
                """
                INSERT INTO scan_runs (
                    run_id, repo_path, commit_sha, app_group, host_fingerprint,
                    status, options_json, summary_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_run_id,
                    canonical_repo,
                    commit_sha_clean,
                    app_group_clean,
                    self.host_fingerprint,
                    "RUNNING",
                    options_json,
                    "{}",
                    now,
                    now,
                ),
            )
            conn.commit()
            created = conn.execute(
                "SELECT * FROM scan_runs WHERE run_id = ?",
                (new_run_id,),
            ).fetchone()
            assert created is not None
            return self._build_run_summary_unlocked(created)

    def save_stage(
        self,
        run_id: str,
        stage_name: str,
        status: str,
        payload: Any = None,
        duration_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StageCheckpointItem:
        if status not in _VALID_STAGE_STATUSES:
            raise ValueError(f"Invalid stage status: {status}")

        payload_json = json.dumps(payload, sort_keys=True, default=str)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        meta_dict = dict(metadata or {})
        metadata_json = json.dumps(meta_dict, sort_keys=True, default=str)
        now = _utc_now_iso()
        dur = float(duration_ms)

        with self._lock:
            conn = self._require_conn_unlocked()
            exists = conn.execute("SELECT 1 FROM scan_runs WHERE run_id = ?", (run_id,)).fetchone()
            if exists is None:
                raise ValueError(f"Unknown scan run_id: {run_id}")

            conn.execute(
                """
                INSERT INTO stage_checkpoints (
                    run_id, stage_name, status, payload_json, payload_sha256,
                    duration_ms, metadata_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, stage_name) DO UPDATE SET
                    status = excluded.status,
                    payload_json = excluded.payload_json,
                    payload_sha256 = excluded.payload_sha256,
                    duration_ms = excluded.duration_ms,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (run_id, stage_name, status, payload_json, payload_sha256, dur, metadata_json, now),
            )
            conn.execute(
                "UPDATE scan_runs SET updated_at = ? WHERE run_id = ?",
                (now, run_id),
            )
            conn.commit()

        return StageCheckpointItem(
            stage_name=stage_name,
            status=status,  # type: ignore[arg-type]
            payload_sha256=payload_sha256,
            duration_ms=dur,
            updated_at=now,
            metadata=meta_dict,
        )

    def get_stage(self, run_id: str, stage_name: str) -> Optional[Tuple[StageCheckpointItem, Any]]:
        with self._lock:
            conn = self._require_conn_unlocked()
            row = conn.execute(
                """
                SELECT stage_name, status, payload_json, payload_sha256,
                       duration_ms, metadata_json, updated_at
                FROM stage_checkpoints
                WHERE run_id = ? AND stage_name = ?
                """,
                (run_id, stage_name),
            ).fetchone()

        if row is None:
            return None

        payload_json = row["payload_json"]
        actual_sha = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        if actual_sha != row["payload_sha256"]:
            return None

        try:
            payload = json.loads(payload_json)
            meta = json.loads(row["metadata_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            return None

        if not isinstance(meta, dict):
            meta = {}

        item = StageCheckpointItem(
            stage_name=row["stage_name"],
            status=row["status"],
            payload_sha256=row["payload_sha256"],
            duration_ms=float(row["duration_ms"]),
            updated_at=row["updated_at"],
            metadata=meta,
        )
        return item, payload

    def mark_run_status(
        self,
        run_id: str,
        status: str,
        summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        if status not in _VALID_RUN_STATUSES:
            raise ValueError(f"Invalid run status: {status}")

        now = _utc_now_iso()
        with self._lock:
            conn = self._require_conn_unlocked()
            if summary is not None:
                summary_json = json.dumps(summary, sort_keys=True, default=str)
                cur = conn.execute(
                    "UPDATE scan_runs SET status = ?, summary_json = ?, updated_at = ? WHERE run_id = ?",
                    (status, summary_json, now, run_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE scan_runs SET status = ?, updated_at = ? WHERE run_id = ?",
                    (status, now, run_id),
                )
            if cur.rowcount == 0:
                raise ValueError(f"Unknown scan run_id: {run_id}")
            conn.commit()

    def get_run(self, run_id: str) -> Optional[ScanRunCheckpointSummary]:
        with self._lock:
            conn = self._require_conn_unlocked()
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                return None
            return self._build_run_summary_unlocked(row)

    def list_runs(
        self,
        repo_path: Optional[str] = None,
        limit: int = 50,
    ) -> List[ScanRunCheckpointSummary]:
        clamped_limit = max(1, min(500, int(limit)))
        with self._lock:
            conn = self._require_conn_unlocked()
            if repo_path:
                canonical_repo = os.path.realpath(repo_path)
                norm_repo = os.path.normcase(canonical_repo)
                rows = conn.execute(
                    "SELECT * FROM scan_runs ORDER BY updated_at DESC, rowid DESC",
                ).fetchall()
                filtered = [r for r in rows if os.path.normcase(r["repo_path"]) == norm_repo][:clamped_limit]
            else:
                filtered = conn.execute(
                    "SELECT * FROM scan_runs ORDER BY updated_at DESC, rowid DESC LIMIT ?",
                    (clamped_limit,),
                ).fetchall()
            return [self._build_run_summary_unlocked(r) for r in filtered]

    def verify_host_provenance(
        self,
        run_id: str,
        repo_path: str,
        current_commit_sha: str,
    ) -> Tuple[bool, str]:
        canonical_repo = os.path.realpath(repo_path)
        with self._lock:
            conn = self._require_conn_unlocked()
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()

        if row is None:
            return False, f"Run '{run_id}' not found in local host checkpoint store"
        if row["host_fingerprint"] != self.host_fingerprint:
            return False, "Host fingerprint mismatch: checkpoint was produced on a foreign host or vault"
        if os.path.normcase(row["repo_path"]) != os.path.normcase(canonical_repo):
            return False, "Repository path mismatch between checkpoint and target repository"
        if row["status"] not in ("COMPLETED", "PARTIAL"):
            return False, f"Checkpoint run status '{row['status']}' is not COMPLETED or PARTIAL"
        if current_commit_sha and row["commit_sha"] != current_commit_sha:
            return (
                False,
                f"Commit SHA mismatch: checkpoint scanned '{row['commit_sha']}', current HEAD is '{current_commit_sha}'",
            )
        return True, "Verified host-produced scan provenance"

    def save_fleet_run(self, fleet_run: FleetRunResponse) -> None:
        summary_json = fleet_run.model_dump_json()
        now = _utc_now_iso()
        with self._lock:
            conn = self._require_conn_unlocked()
            conn.execute(
                """
                INSERT INTO fleet_runs (
                    fleet_run_id, manifest_name, status, total_repos,
                    completed_repos, failed_repos, summary_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fleet_run_id) DO UPDATE SET
                    manifest_name = excluded.manifest_name,
                    status = excluded.status,
                    total_repos = excluded.total_repos,
                    completed_repos = excluded.completed_repos,
                    failed_repos = excluded.failed_repos,
                    summary_json = excluded.summary_json,
                    updated_at = excluded.updated_at
                """,
                (
                    fleet_run.fleet_run_id,
                    fleet_run.manifest_name,
                    fleet_run.status,
                    fleet_run.total_repos,
                    fleet_run.completed_repos,
                    fleet_run.failed_repos,
                    summary_json,
                    fleet_run.created_at,
                    now,
                ),
            )
            conn.commit()

    def list_fleet_runs(self, limit: int = 30) -> FleetRunListResponse:
        clamped_limit = max(1, min(500, int(limit)))
        with self._lock:
            conn = self._require_conn_unlocked()
            total_row = conn.execute("SELECT COUNT(*) AS cnt FROM fleet_runs").fetchone()
            total = int(total_row["cnt"]) if total_row is not None else 0
            rows = conn.execute(
                "SELECT summary_json FROM fleet_runs ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (clamped_limit,),
            ).fetchall()

        runs: List[FleetRunResponse] = []
        for row in rows:
            runs.append(FleetRunResponse.model_validate_json(row["summary_json"]))
        return FleetRunListResponse(total=total, runs=runs)

    def gc(
        self,
        older_than_days: int = 30,
        keep_last: int = 20,
        dry_run: bool = False,
        temp_workspaces_parent: Optional[str] = None,
    ) -> GcReport:
        keep_n = max(0, int(keep_last))
        days_n = max(0, int(older_than_days))
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days_n)

        warnings: List[str] = []
        pruned_temp_dirs = 0
        reclaimed_bytes = 0

        with self._lock:
            conn = self._require_conn_unlocked()
            all_rows = conn.execute(
                "SELECT run_id, updated_at FROM scan_runs ORDER BY updated_at DESC, rowid DESC"
            ).fetchall()

            prune_run_ids: List[str] = []
            for row in all_rows[keep_n:]:
                row_dt = _parse_iso_utc(row["updated_at"])
                if row_dt is None or row_dt <= cutoff_dt:
                    prune_run_ids.append(row["run_id"])

            pruned_checkpoints = 0
            for rid in prune_run_ids:
                cnt_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM stage_checkpoints WHERE run_id = ?",
                    (rid,),
                ).fetchone()
                if cnt_row is not None:
                    pruned_checkpoints += int(cnt_row["cnt"])

            if not dry_run and prune_run_ids:
                for rid in prune_run_ids:
                    conn.execute("DELETE FROM scan_runs WHERE run_id = ?", (rid,))
                conn.commit()

            kept_runs = len(all_rows) - len(prune_run_ids)

        if temp_workspaces_parent:
            if is_link_or_junction(temp_workspaces_parent):
                warnings.append(
                    f"Skipped temp_workspaces_parent because it is a symlink/junction: {temp_workspaces_parent}"
                )
            elif os.path.isdir(temp_workspaces_parent):
                real_parent = os.path.realpath(temp_workspaces_parent)
                try:
                    with os.scandir(real_parent) as it:
                        entries = list(it)
                except OSError as exc:
                    entries = []
                    warnings.append(f"Failed scanning temp_workspaces_parent: {exc}")

                for entry in entries:
                    if is_entry_link_or_junction(entry):
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        warnings.append(f"Unable to stat temp dir '{entry.name}': {exc}")
                        continue
                    mtime_dt = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                    if mtime_dt <= cutoff_dt:
                        if dry_run:
                            reclaimed_bytes += _measure_dir_bytes_no_follow(entry.path)
                            pruned_temp_dirs += 1
                        else:
                            try:
                                reclaimed_bytes += safe_cleanup_workspace(entry.path, real_parent)
                                pruned_temp_dirs += 1
                            except (HostileRepoError, OSError) as exc:
                                warnings.append(f"Failed cleaning temp dir '{entry.name}': {exc}")

        return GcReport(
            dry_run=dry_run,
            pruned_runs=len(prune_run_ids),
            pruned_checkpoints=pruned_checkpoints,
            pruned_temp_dirs=pruned_temp_dirs,
            reclaimed_bytes=reclaimed_bytes,
            kept_runs=kept_runs,
            warnings=warnings,
        )
