"""
ALASTOR v5.0 Pillar 4 — Hostile-Repo Isolation & Sandboxed Execution Guardrails.

Protects the host and CI runners when inspecting untrusted target repositories:
1. Hardened `git` subprocess builder neutralizing `core.fsmonitor`, `core.hooksPath`,
   `core.sshCommand`, `diff.external`, `credential.helper`, `filter.*`, and `diff.*` drivers
   via `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`.
2. Refusal to load `.env`, `.alastor.yaml`, `config.yaml`, or any config located inside
   the scanned target repository (including symlink traversal).
3. Strict remote clone URL validation (`http://`, `https://`, `ssh://`, `git@host:owner/repo`).
4. Symlink- and NTFS-junction-escape-proof workspace cleanup with read-only pack handling.
5. Hardened opt-in Docker sandbox argv builder (`--read-only`, `--cap-drop=ALL`, `--network=none`).
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from typing import Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple
from urllib.parse import urlsplit


class HostileRepoError(ValueError):
    """Raised when an untrusted repository, URL, config source, or path violates isolation policy."""


class HardenedGitCommand(NamedTuple):
    argv: List[str]
    env: Dict[str, str]


_BASE_GIT_PINS: Tuple[Tuple[str, str], ...] = (
    ("core.fsmonitor", ""),
    ("core.hooksPath", "/dev/null"),
    ("core.sshCommand", "false"),
    ("diff.external", ""),
    ("credential.helper", ""),
)

_FORCED_BASE_KEYS_LOWER = {k.lower() for k, _ in _BASE_GIT_PINS}
_FILTER_KEY_RE = re.compile(r"^filter\.(.+)\.(clean|smudge|process|required)$", re.IGNORECASE)
_DIFF_KEY_RE = re.compile(r"^diff\.(.+)\.(textconv|command)$", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SCP_CLONE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)@([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):([A-Za-z0-9_./-]+)$"
)
_HOSTILE_CONFIG_FILENAMES: Tuple[str, ...] = (".env", ".env.local", ".alastor.yaml", "config.yaml")


def _validate_no_control_chars(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise HostileRepoError(f"{label} must be a non-empty string")
    if any(ch in value for ch in ("\r", "\n", "\x00")):
        raise HostileRepoError(f"{label} contains forbidden control characters")
    return value


def is_link_or_junction(path: str) -> bool:
    """Return True if `path` is a POSIX/NTFS symlink or Windows directory junction."""
    return os.path.islink(path) or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def is_entry_link_or_junction(entry: os.DirEntry[str]) -> bool:
    """Return True if a `scandir` entry is a symlink or Windows directory junction."""
    return (
        entry.is_symlink()
        or (hasattr(entry, "is_junction") and entry.is_junction())
        or is_link_or_junction(entry.path)
    )


_is_link_or_junction = is_link_or_junction
_is_entry_link_or_junction = is_entry_link_or_junction


def _is_same_or_inside(candidate: str, root: str) -> bool:
    nc = os.path.normcase(candidate)
    nr = os.path.normcase(root)
    try:
        return os.path.commonpath([nc, nr]) == nr
    except ValueError:
        return False


def _is_strictly_inside(candidate: str, root: str) -> bool:
    nc = os.path.normcase(candidate)
    nr = os.path.normcase(root)
    if nc == nr:
        return False
    return _is_same_or_inside(candidate, root)


def _lookup_env_case_insensitive(env_map: Mapping[str, str], target_key: str) -> Optional[str]:
    if target_key in env_map:
        return env_map[target_key]
    upper_target = target_key.upper()
    for k, v in env_map.items():
        if k.upper() == upper_target:
            return v
    return None


def _extract_preserved_git_config_pins(source_env: Mapping[str, str]) -> List[Tuple[str, str]]:
    raw_count = _lookup_env_case_insensitive(source_env, "GIT_CONFIG_COUNT")
    if raw_count is None:
        return []
    try:
        count = int(raw_count)
    except (TypeError, ValueError):
        return []
    if count <= 0:
        return []
    count = min(count, 1024)
    pins: List[Tuple[str, str]] = []
    for idx in range(count):
        key = _lookup_env_case_insensitive(source_env, f"GIT_CONFIG_KEY_{idx}")
        if not key or "\x00" in key or "\n" in key or "\r" in key:
            continue
        val = _lookup_env_case_insensitive(source_env, f"GIT_CONFIG_VALUE_{idx}")
        pins.append((key, "" if val is None else str(val)))
    return pins


def _apply_git_config_pins(env: Dict[str, str], pins: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    out = dict(env)
    out["GIT_CONFIG_COUNT"] = str(len(pins))
    for idx, (key, val) in enumerate(pins):
        out[f"GIT_CONFIG_KEY_{idx}"] = key
        out[f"GIT_CONFIG_VALUE_{idx}"] = val
    return out


def _is_neutralized_config_key(key: str) -> bool:
    lower = key.lower()
    return (
        lower in _FORCED_BASE_KEYS_LOWER
        or bool(_FILTER_KEY_RE.match(key))
        or bool(_DIFF_KEY_RE.match(key))
    )


def build_hardened_git_env_and_argv(
    repo_path: str,
    environ: Optional[Mapping[str, str]] = None,
    timeout: int = 30,
) -> HardenedGitCommand:
    """
    Construct a sanitized `git -C <repo>` command and environment that strips hostile
    `GIT_*` env vars and neutralizes `.git/config` hook/filter/diff/fsmonitor execution.
    """
    _validate_no_control_chars(repo_path, "repo_path")
    real_repo = os.path.realpath(repo_path)
    if not os.path.isdir(real_repo):
        raise HostileRepoError(f"Repository path does not exist or is not a directory: {repo_path}")

    source_env: Mapping[str, str] = os.environ if environ is None else environ
    clean_env: Dict[str, str] = {
        str(k): str(v) for k, v in source_env.items() if not str(k).upper().startswith("GIT_")
    }
    preserved_pins = [
        (k, v)
        for k, v in _extract_preserved_git_config_pins(source_env)
        if not _is_neutralized_config_key(k)
    ]

    base_pins: List[Tuple[str, str]] = list(preserved_pins) + list(_BASE_GIT_PINS)
    base_env = _apply_git_config_pins(clean_env, base_pins)

    try:
        probe = subprocess.run(
            ["git", "-C", real_repo, "config", "--null", "--list"],
            env=base_env,
            shell=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostileRepoError(f"Hardened git config inspection failed: {exc}") from exc

    if probe.returncode != 0:
        err_text = (probe.stderr or b"").decode("utf-8", errors="replace").strip()
        raise HostileRepoError(f"Hardened git config inspection exited {probe.returncode}: {err_text}")

    dynamic_pins: List[Tuple[str, str]] = []
    seen_dynamic: set[str] = set()
    raw_entries = probe.stdout.decode("utf-8", errors="replace").split("\x00")
    for entry in raw_entries:
        if not entry:
            continue
        key = entry.split("\n", 1)[0].strip()
        if not key:
            continue
        key_lower = key.lower()
        if key_lower in seen_dynamic:
            continue
        filter_match = _FILTER_KEY_RE.match(key)
        if filter_match:
            subkey = filter_match.group(2).lower()
            dynamic_pins.append((key, "false" if subkey == "required" else ""))
            seen_dynamic.add(key_lower)
            continue
        if _DIFF_KEY_RE.match(key):
            dynamic_pins.append((key, ""))
            seen_dynamic.add(key_lower)

    final_env = _apply_git_config_pins(clean_env, base_pins + dynamic_pins)
    return HardenedGitCommand(argv=["git", "-C", real_repo], env=final_env)


def run_hardened_git(
    repo_path: str,
    git_args: Sequence[str],
    timeout: int = 30,
    environ: Optional[Mapping[str, str]] = None,
) -> subprocess.CompletedProcess:
    """Execute a git subcommand inside `repo_path` with all hostile config drivers neutralized."""
    clean_args: List[str] = []
    for arg in git_args:
        arg_str = str(arg)
        if "\x00" in arg_str:
            raise HostileRepoError("git argument contains NUL byte")
        clean_args.append(arg_str)

    hardened = build_hardened_git_env_and_argv(repo_path=repo_path, environ=environ, timeout=timeout)
    try:
        return subprocess.run(
            [*hardened.argv, *clean_args],
            env=hardened.env,
            shell=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostileRepoError(f"Hardened git execution failed: {exc}") from exc


def get_repo_commit_sha(repo_path: str) -> str:
    """Return HEAD commit SHA using hardened git, or '' if not a git repository / no commits."""
    proc = run_hardened_git(repo_path, ["rev-parse", "HEAD"])
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def assert_safe_config_source(config_path: str, repo_root: str) -> str:
    """
    Refuse loading any `.env`, `.alastor.yaml`, `config.yaml`, or configuration path
    located inside (or resolving into) the scanned target repository.
    """
    _validate_no_control_chars(config_path, "config_path")
    _validate_no_control_chars(repo_root, "repo_root")

    real_repo = os.path.realpath(repo_root)
    real_cfg = os.path.realpath(config_path)
    abs_cfg_parent = os.path.realpath(os.path.dirname(os.path.abspath(config_path)))

    if _is_same_or_inside(real_cfg, real_repo) or _is_same_or_inside(abs_cfg_parent, real_repo):
        raise HostileRepoError(
            f"Refused configuration source inside scanned target repository: {config_path}"
        )
    return real_cfg


def find_hostile_target_configs(repo_root: str) -> List[str]:
    """
    Return relative paths of untrusted config/hook artifacts present inside `repo_root`
    for informational warnings only; never reads or executes them.
    """
    if not repo_root or not os.path.isdir(repo_root):
        return []

    found: List[str] = []
    for filename in _HOSTILE_CONFIG_FILENAMES:
        candidate = os.path.join(repo_root, filename)
        if os.path.lexists(candidate):
            found.append(filename)

    hooks_dir = os.path.join(repo_root, ".git", "hooks")
    if os.path.isdir(hooks_dir) and not _is_link_or_junction(hooks_dir):
        try:
            with os.scandir(hooks_dir) as it:
                for entry in it:
                    if entry.name.lower().endswith(".sample"):
                        continue
                    if entry.is_file(follow_symlinks=False) or _is_entry_link_or_junction(entry):
                        found.append(f".git/hooks/{entry.name}")
        except OSError:
            pass

    return sorted(found)


def validate_clone_url(url: str) -> str:
    """
    Validate a remote git clone URL against an explicit scheme/syntax allowlist.
    Blocks option injection (`-...`), control chars, local paths, `file://`, `ext::`,
    `fd::`, `git::`, and embedded credentials in HTTP(S) URLs.
    """
    if not isinstance(url, str):
        raise HostileRepoError("Clone URL must be a string")
    if any(ch in url for ch in ("\r", "\n", "\x00", "\t", "\v", "\f")):
        raise HostileRepoError("Clone URL contains forbidden control or newline characters")

    cleaned = url.strip(" ")
    if not cleaned:
        raise HostileRepoError("Clone URL cannot be empty")
    if any(ch.isspace() for ch in cleaned):
        raise HostileRepoError("Clone URL cannot contain internal whitespace")
    if cleaned.startswith("-"):
        raise HostileRepoError("Clone URL cannot start with '-' (option injection blocked)")
    if "\\" in cleaned:
        raise HostileRepoError("Clone URL cannot contain backslashes")

    lower = cleaned.lower()
    if lower.startswith(("file://", "ext::", "fd::", "git::", "ftp://", "ftps://", "git://")):
        raise HostileRepoError(f"Unsupported or dangerous git transport in URL: {cleaned}")

    if "://" in cleaned:
        parsed = urlsplit(cleaned)
        scheme = parsed.scheme.lower()
        if scheme not in ("https", "http", "ssh"):
            raise HostileRepoError(f"Unsupported clone URL scheme '{scheme}'")
        if parsed.query or parsed.fragment:
            raise HostileRepoError("Clone URL cannot contain query strings or fragments")
        if scheme in ("http", "https"):
            if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
                raise HostileRepoError("Embedded credentials in HTTP(S) clone URL are forbidden")
        else:
            if parsed.password is not None:
                raise HostileRepoError("Embedded passwords in SSH clone URL are forbidden")
            if parsed.username is not None and not _SSH_USER_RE.match(parsed.username):
                raise HostileRepoError("Invalid SSH username in clone URL")

        try:
            _ = parsed.port
        except ValueError as exc:
            raise HostileRepoError(f"Invalid port in clone URL: {exc}") from exc

        hostname = parsed.hostname or ""
        if not hostname or not _HOSTNAME_RE.match(hostname):
            raise HostileRepoError(f"Invalid hostname in clone URL: '{hostname}'")

        path = parsed.path or ""
        if not path or path == "/":
            raise HostileRepoError("Clone URL must include a repository path")
        segments = [seg for seg in path.split("/") if seg]
        if not segments or any(seg in (".", "..") or seg.startswith("-") for seg in segments):
            raise HostileRepoError("Clone URL contains unsafe path segments")
        return cleaned

    if "::" in cleaned:
        raise HostileRepoError("Git remote-helper '::' syntax is forbidden")

    scp_match = _SCP_CLONE_RE.match(cleaned)
    if not scp_match:
        raise HostileRepoError(f"Invalid or local clone URL rejected: {cleaned}")

    repo_path = scp_match.group(3)
    if repo_path.startswith(("/", "-", ".")) or repo_path.endswith("/") or "//" in repo_path:
        raise HostileRepoError("Clone URL contains invalid SCP repository path")
    segments = repo_path.split("/")
    if len(segments) < 2 or any(seg in ("", ".", "..") or seg.startswith("-") for seg in segments):
        raise HostileRepoError("Clone URL contains unsafe SCP path segments")
    return cleaned


def _unlink_or_rmdir_link(path: str) -> None:
    try:
        os.unlink(path)
    except PermissionError:
        os.chmod(path, stat.S_IWRITE)
        try:
            os.unlink(path)
        except OSError:
            os.rmdir(path)
    except OSError:
        os.rmdir(path)


def _remove_file_with_readonly_retry(path: str) -> int:
    try:
        size = os.lstat(path).st_size
    except OSError:
        size = 0
    try:
        os.unlink(path)
    except PermissionError:
        os.chmod(path, stat.S_IWRITE)
        os.unlink(path)
    return size


def _remove_dir_recursive_no_follow(dir_path: str) -> int:
    reclaimed = 0
    with os.scandir(dir_path) as it:
        for entry in it:
            if _is_entry_link_or_junction(entry):
                _unlink_or_rmdir_link(entry.path)
            elif entry.is_dir(follow_symlinks=False):
                reclaimed += _remove_dir_recursive_no_follow(entry.path)
                try:
                    os.rmdir(entry.path)
                except PermissionError:
                    os.chmod(entry.path, stat.S_IWRITE | stat.S_IRUSR | stat.S_IXUSR)
                    os.rmdir(entry.path)
            else:
                reclaimed += _remove_file_with_readonly_retry(entry.path)
    return reclaimed


def safe_cleanup_workspace(workspace_dir: str, allowed_parent: str) -> int:
    """
    Safely delete `workspace_dir` strictly inside `allowed_parent` without ever following
    symlinks or Windows NTFS junctions, handling read-only `.git` pack files cleanly.
    Returns total reclaimed bytes (or 0 if `workspace_dir` is already absent).
    """
    _validate_no_control_chars(workspace_dir, "workspace_dir")
    _validate_no_control_chars(allowed_parent, "allowed_parent")

    if not os.path.isdir(allowed_parent) or _is_link_or_junction(allowed_parent):
        raise HostileRepoError(f"allowed_parent must be an existing non-symlink directory: {allowed_parent}")

    real_parent = os.path.realpath(allowed_parent)
    abs_ws = os.path.abspath(workspace_dir)
    real_ws = os.path.realpath(abs_ws)
    real_ws_parent = os.path.realpath(os.path.dirname(abs_ws))

    if not _is_same_or_inside(real_ws_parent, real_parent):
        raise HostileRepoError(f"Refusing cleanup outside allowed_parent: {workspace_dir}")
    if not _is_strictly_inside(real_ws, real_parent):
        raise HostileRepoError(f"Refusing cleanup of allowed_parent or path outside it: {workspace_dir}")
    if _is_link_or_junction(abs_ws):
        raise HostileRepoError(f"Refusing cleanup of symlink/junction workspace root: {workspace_dir}")

    if not os.path.lexists(abs_ws):
        return 0

    if not os.path.isdir(abs_ws):
        return _remove_file_with_readonly_retry(abs_ws)

    reclaimed = _remove_dir_recursive_no_follow(abs_ws)
    try:
        os.rmdir(abs_ws)
    except PermissionError:
        os.chmod(abs_ws, stat.S_IWRITE | stat.S_IRUSR | stat.S_IXUSR)
        os.rmdir(abs_ws)
    return reclaimed


def build_sandbox_docker_command(
    repo_path: str,
    output_dir: str,
    image: str = "alastor-scanner:v5",
    allow_egress_hosts: Optional[List[str]] = None,
    cli_args: Optional[List[str]] = None,
) -> List[str]:
    """
    Build a hardened `docker run` argv list with read-only rootfs, dropped capabilities,
    no-new-privileges, PID/memory caps, `:ro` repo mount, and `--network=none` by default.
    """
    _validate_no_control_chars(repo_path, "repo_path")
    _validate_no_control_chars(output_dir, "output_dir")
    _validate_no_control_chars(image, "image")
    if image.startswith("-"):
        raise HostileRepoError("Docker image name cannot start with '-'")

    real_repo = os.path.realpath(repo_path)
    real_out = os.path.realpath(output_dir)

    argv: List[str] = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=512m",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=256",
        "--memory=2g",
    ]

    clean_hosts: List[str] = []
    for host in allow_egress_hosts or []:
        h = host.strip()
        if not h:
            continue
        _validate_no_control_chars(h, "allow_egress_host")
        if any(ch.isspace() or ch == "," for ch in h):
            raise HostileRepoError(f"Invalid egress host specification: {h}")
        clean_hosts.append(h)

    if not clean_hosts:
        argv.append("--network=none")
    else:
        argv.extend(["--env", f"ALASTOR_ALLOWED_EGRESS={','.join(clean_hosts)}"])

    argv.extend(
        [
            "-v",
            f"{real_repo}:/workspace:ro",
            "-v",
            f"{real_out}:/out:rw",
            image,
        ]
    )

    final_cli_args = cli_args if cli_args is not None else ["scan", "--repo", "/workspace", "--out", "/out"]
    for item in final_cli_args:
        _validate_no_control_chars(str(item), "cli_arg")
        argv.append(str(item))

    return argv
