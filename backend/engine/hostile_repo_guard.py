"""
ALASTOR v5.0 Pillar 4 — Hostile-Repo Isolation & Sandboxed Execution Guardrails.

Protects the host and CI runners when inspecting untrusted target repositories:
1. Hardened `git` subprocess builder neutralizing `core.fsmonitor`, `core.hooksPath`,
   `core.sshCommand`, `core.pager`, `core.editor`, `sequence.editor`, `core.gitProxy`,
   `core.askPass`, `core.alternateRefsCommand`, `uploadpack.packObjectsHook`,
   `gpg.program`, `protocol.allow`, `diff.external`, `credential.helper`, `filter.*`,
   `diff.*`, `pager.*`, `remote.*`, `credential.*.helper`, `gpg.*.program`, `merge.*.driver`,
   `protocol.*.allow`, and `url.*.insteadOf` / `pushInsteadOf` via `GIT_CONFIG_COUNT`.
2. Refusal to load `.env`, `.alastor.yaml`, `config.yaml`, or any config located inside
   the scanned target repository (including nested symlink/junction traversal).
3. Strict remote clone URL validation (`http://`, `https://`, `ssh://`, `git@host:owner/repo`).
4. Symlink- and NTFS-junction-escape-proof workspace cleanup with read-only dir/pack handling.
5. Hardened opt-in Docker sandbox argv builder (`--read-only`, `--cap-drop=ALL`, `--network=none`).
"""
from __future__ import annotations

import ipaddress
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
    ("credential.helper", ""),
    ("core.pager", ""),
    ("core.editor", "false"),
    ("sequence.editor", "false"),
    ("core.gitProxy", ""),
    ("core.askPass", ""),
    ("core.alternateRefsCommand", ""),
    ("uploadpack.packObjectsHook", ""),
    ("gpg.program", "false"),
    ("protocol.allow", "user"),
    ("protocol.file.allow", "never"),
    ("protocol.ext.allow", "never"),
    ("protocol.fd.allow", "never"),
    ("protocol.git.allow", "never"),
)

_FORCED_BASE_KEYS_LOWER = {k.lower() for k, _ in _BASE_GIT_PINS}
_SAFE_GIT_PROTOCOLS = {"http", "https", "ssh"}

_FILTER_KEY_RE = re.compile(r"^filter\.(.+)\.(clean|smudge|process|required)$", re.IGNORECASE)
_DIFF_SECTION_KEY_RE = re.compile(r"^diff\.(.+)\.(textconv|command)$", re.IGNORECASE)
_PAGER_KEY_RE = re.compile(r"^pager\.(.+)$", re.IGNORECASE)
_REMOTE_KEY_RE = re.compile(r"^remote\.(.+)\.(uploadpack|receivepack|vcs|proxy)$", re.IGNORECASE)
_CREDENTIAL_SECTION_KEY_RE = re.compile(r"^credential\.(.+)\.helper$", re.IGNORECASE)
_GPG_SECTION_KEY_RE = re.compile(r"^gpg\.(.+)\.program$", re.IGNORECASE)
_MERGE_KEY_RE = re.compile(r"^merge\.(.+)\.driver$", re.IGNORECASE)
_PROTOCOL_SECTION_KEY_RE = re.compile(r"^protocol\.(.+)\.allow$", re.IGNORECASE)
_URL_REWRITE_KEY_RE = re.compile(r"^url\.(.+)\.(insteadof|pushinsteadof)$", re.IGNORECASE)

_GIT_GLOBAL_OPTS_WITH_ARG = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--exec-path",
}
_DIFF_TEXTCONV_SUBCOMMANDS = {"diff", "log", "show"}

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SCP_CLONE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)@([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):([A-Za-z0-9_./-]+)$"
)
_DOCKER_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
_WINDOWS_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:[\\/]")
_CLOUD_METADATA_HOSTS = {"169.254.169.254", "100.100.100.200", "metadata.google.internal", "metadata"}
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


def _canonical_git_config_key(key: str) -> str:
    """
    Preserve Git's exact case semantics: section and variable are case-insensitive,
    while any subsection (including dots inside URLs) is case-sensitive.
    """
    first_dot = key.find(".")
    last_dot = key.rfind(".")
    if first_dot == -1:
        return key.lower()
    if first_dot == last_dot:
        return key.lower()
    section = key[:first_dot].lower()
    subsection = key[first_dot + 1 : last_dot]
    variable = key[last_dot + 1 :].lower()
    return f"{section}.{subsection}.{variable}"


def _neutralized_value_for_dynamic_key(key: str) -> Optional[str]:
    lower = key.lower()
    if lower == "diff.external":
        return ""
    filter_match = _FILTER_KEY_RE.match(key)
    if filter_match:
        return "false" if filter_match.group(2).lower() == "required" else ""
    if _DIFF_SECTION_KEY_RE.match(key):
        return ""
    if _PAGER_KEY_RE.match(key):
        return "false"
    if _REMOTE_KEY_RE.match(key):
        return ""
    if _CREDENTIAL_SECTION_KEY_RE.match(key):
        return ""
    if _GPG_SECTION_KEY_RE.match(key):
        return "false"
    if _MERGE_KEY_RE.match(key):
        return "false"
    proto_match = _PROTOCOL_SECTION_KEY_RE.match(key)
    if proto_match:
        proto_name = proto_match.group(1).lower()
        return "user" if proto_name in _SAFE_GIT_PROTOCOLS else "never"
    if _URL_REWRITE_KEY_RE.match(key):
        return ""
    return None


def _is_neutralized_config_key(key: str) -> bool:
    lower = key.lower()
    if lower in _FORCED_BASE_KEYS_LOWER:
        return True
    return _neutralized_value_for_dynamic_key(key) is not None


def build_hardened_git_env_and_argv(
    repo_path: str,
    environ: Optional[Mapping[str, str]] = None,
    timeout: int = 30,
) -> HardenedGitCommand:
    """
    Construct a sanitized `git -C <repo>` command and environment that strips hostile
    `GIT_*` env vars and neutralizes `.git/config` hook/filter/diff/pager/remote/protocol drivers.
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
    seen_dynamic: set[str] = set(_FORCED_BASE_KEYS_LOWER)
    raw_entries = probe.stdout.decode("utf-8", errors="replace").split("\x00")
    for entry in raw_entries:
        if not entry:
            continue
        key = entry.split("\n", 1)[0].strip()
        if not key:
            continue
        canon_key = _canonical_git_config_key(key)
        if canon_key in seen_dynamic:
            continue
        neutral_val = _neutralized_value_for_dynamic_key(key)
        if neutral_val is not None:
            dynamic_pins.append((key, neutral_val))
            seen_dynamic.add(canon_key)

    final_env = _apply_git_config_pins(clean_env, base_pins + dynamic_pins)
    return HardenedGitCommand(argv=["git", "-C", real_repo], env=final_env)


def _inject_safe_diff_flags(clean_args: Sequence[str]) -> List[str]:
    args_list = list(clean_args)
    idx = 0
    subcmd_idx: Optional[int] = None
    while idx < len(args_list):
        tok = args_list[idx]
        if tok == "--":
            break
        if tok in _GIT_GLOBAL_OPTS_WITH_ARG:
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        subcmd_idx = idx
        break

    if subcmd_idx is None or args_list[subcmd_idx] not in _DIFF_TEXTCONV_SUBCOMMANDS:
        return args_list

    # Only inspect flags before `--` so filenames after `--` are never treated as options.
    end_opts = args_list.index("--") if "--" in args_list else len(args_list)
    existing_opts = set(args_list[subcmd_idx + 1 : end_opts])
    to_insert: List[str] = []
    if "--no-ext-diff" not in existing_opts:
        to_insert.append("--no-ext-diff")
    if "--no-textconv" not in existing_opts:
        to_insert.append("--no-textconv")
    if not to_insert:
        return args_list
    return args_list[: subcmd_idx + 1] + to_insert + args_list[subcmd_idx + 1 :]


def run_hardened_git(
    repo_path: str,
    git_args: Sequence[str],
    timeout: int = 30,
    environ: Optional[Mapping[str, str]] = None,
) -> subprocess.CompletedProcess:
    """Execute a git subcommand inside `repo_path` with all hostile config drivers neutralized."""
    clean_args: List[str] = []
    for arg in git_args:
        if not isinstance(arg, str):
            raise HostileRepoError("git argument must be a string")
        if "\x00" in arg:
            raise HostileRepoError("git argument contains NUL byte")
        clean_args.append(arg)

    safe_args = _inject_safe_diff_flags(clean_args)
    hardened = build_hardened_git_env_and_argv(repo_path=repo_path, environ=environ, timeout=timeout)
    try:
        return subprocess.run(
            [*hardened.argv, *safe_args],
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


def _iter_raw_prefixes(raw_path: str) -> List[str]:
    """Build cumulative path prefixes without collapsing `..` segments."""
    joined = raw_path if os.path.isabs(raw_path) else os.path.join(os.getcwd(), raw_path)
    drive, rest = os.path.splitdrive(joined)
    if drive:
        anchor = drive + (os.sep if rest.startswith(("/", "\\")) else "")
        tail = rest.lstrip("/\\")
    elif joined.startswith(("/", "\\")):
        anchor = os.sep
        tail = rest.lstrip("/\\")
    else:
        anchor = ""
        tail = rest

    prefixes: List[str] = []
    cursor = anchor
    for segment in re.split(r"[\\/]+", tail):
        if not segment or segment == ".":
            continue
        cursor = os.path.join(cursor, segment) if cursor else segment
        prefixes.append(cursor)
    return prefixes


def assert_safe_config_source(config_path: str, repo_root: str) -> str:
    """
    Refuse loading any `.env`, `.alastor.yaml`, `config.yaml`, or configuration path
    located inside, resolving into, or traversing through the scanned target repository.
    """
    _validate_no_control_chars(config_path, "config_path")
    _validate_no_control_chars(repo_root, "repo_root")

    abs_repo = os.path.abspath(repo_root)
    real_repo = os.path.realpath(repo_root)
    abs_cfg = os.path.abspath(config_path)
    real_cfg = os.path.realpath(config_path)
    real_cfg_parent = os.path.realpath(os.path.dirname(abs_cfg))

    for candidate in (abs_cfg, real_cfg, real_cfg_parent):
        if _is_same_or_inside(candidate, abs_repo) or _is_same_or_inside(candidate, real_repo):
            raise HostileRepoError(
                f"Refused configuration source inside scanned target repository: {config_path}"
            )

    # Walk un-normalized prefixes to catch nested `<repo>/junc/sub/config.yaml` or `<repo>/junc/../outside`.
    for prefix in _iter_raw_prefixes(config_path):
        norm_prefix = os.path.normpath(prefix)
        real_prefix = os.path.realpath(prefix)
        in_repo = (
            _is_same_or_inside(norm_prefix, abs_repo)
            or _is_same_or_inside(norm_prefix, real_repo)
            or _is_same_or_inside(real_prefix, abs_repo)
            or _is_same_or_inside(real_prefix, real_repo)
        )
        if in_repo:
            if os.path.lexists(prefix) and is_link_or_junction(prefix):
                raise HostileRepoError(
                    f"Refused configuration source traversing symlink/junction inside repository: {config_path}"
                )
            raise HostileRepoError(
                f"Refused configuration source inside scanned target repository: {config_path}"
            )

    return real_cfg


def find_hostile_target_configs(repo_root: str) -> List[str]:
    """
    Return relative paths of untrusted config/hook artifacts present inside `repo_root`
    for informational warnings only; never reads or executes them.
    """
    if not repo_root or not os.path.isdir(repo_root) or is_link_or_junction(repo_root):
        return []

    found: List[str] = []
    for filename in _HOSTILE_CONFIG_FILENAMES:
        candidate = os.path.join(repo_root, filename)
        if os.path.lexists(candidate):
            found.append(filename)

    git_dir = os.path.join(repo_root, ".git")
    hooks_dir = os.path.join(git_dir, "hooks")
    if (
        os.path.isdir(git_dir)
        and not is_link_or_junction(git_dir)
        and os.path.isdir(hooks_dir)
        and not is_link_or_junction(hooks_dir)
    ):
        try:
            with os.scandir(hooks_dir) as it:
                for entry in it:
                    if entry.name.lower().endswith(".sample"):
                        continue
                    if entry.is_file(follow_symlinks=False) or is_entry_link_or_junction(entry):
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
    """Remove a symlink or NTFS junction itself; never chmod a symlink target."""
    try:
        os.unlink(path)
    except OSError:
        os.rmdir(path)


def _remove_file_with_readonly_retry(path: str) -> int:
    if is_link_or_junction(path):
        raise HostileRepoError(f"Refusing file-removal chmod on symlink/junction: {path}")
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


def _ensure_real_dir_rw_exec(dir_path: str) -> None:
    if is_link_or_junction(dir_path):
        raise HostileRepoError(f"Refusing chmod on symlink/junction directory: {dir_path}")
    try:
        st = os.lstat(dir_path)
        if stat.S_ISDIR(st.st_mode) and (st.st_mode & stat.S_IRWXU) != stat.S_IRWXU:
            os.chmod(dir_path, st.st_mode | stat.S_IRWXU)
    except OSError:
        pass


def _remove_dir_recursive_no_follow(dir_path: str) -> int:
    _ensure_real_dir_rw_exec(dir_path)
    reclaimed = 0
    with os.scandir(dir_path) as it:
        for entry in it:
            if is_entry_link_or_junction(entry):
                _unlink_or_rmdir_link(entry.path)
            elif entry.is_dir(follow_symlinks=False):
                reclaimed += _remove_dir_recursive_no_follow(entry.path)
                try:
                    os.rmdir(entry.path)
                except PermissionError:
                    os.chmod(entry.path, stat.S_IRWXU)
                    os.rmdir(entry.path)
            else:
                reclaimed += _remove_file_with_readonly_retry(entry.path)
    return reclaimed


def safe_cleanup_workspace(workspace_dir: str, allowed_parent: str) -> int:
    """
    Safely delete `workspace_dir` strictly inside `allowed_parent` without ever following
    symlinks or Windows NTFS junctions, handling read-only directories and `.git` pack files.
    Returns total reclaimed bytes (or 0 if `workspace_dir` is already absent).
    """
    _validate_no_control_chars(workspace_dir, "workspace_dir")
    _validate_no_control_chars(allowed_parent, "allowed_parent")

    if not os.path.isdir(allowed_parent) or is_link_or_junction(allowed_parent):
        raise HostileRepoError(f"allowed_parent must be an existing non-symlink directory: {allowed_parent}")

    abs_parent = os.path.abspath(allowed_parent)
    real_parent = os.path.realpath(allowed_parent)
    abs_ws = os.path.abspath(workspace_dir)
    real_ws = os.path.realpath(abs_ws)
    real_ws_parent = os.path.realpath(os.path.dirname(abs_ws))

    if not _is_same_or_inside(real_ws_parent, real_parent):
        raise HostileRepoError(f"Refusing cleanup outside allowed_parent: {workspace_dir}")
    if not _is_strictly_inside(real_ws, real_parent):
        raise HostileRepoError(f"Refusing cleanup of allowed_parent or path outside it: {workspace_dir}")

    if _is_strictly_inside(abs_ws, real_parent):
        walk_base = real_parent
    elif _is_strictly_inside(abs_ws, abs_parent):
        walk_base = abs_parent
    else:
        raise HostileRepoError(f"Refusing cleanup outside allowed_parent: {workspace_dir}")

    rel_ws = os.path.relpath(abs_ws, walk_base)
    cursor = walk_base
    for part in rel_ws.split(os.sep):
        if not part or part == ".":
            continue
        if part == "..":
            raise HostileRepoError(f"Refusing path traversal in workspace_dir: {workspace_dir}")
        cursor = os.path.join(cursor, part)
        if os.path.lexists(cursor) and is_link_or_junction(cursor):
            raise HostileRepoError(f"Refusing cleanup of symlink/junction path component: {cursor}")

    if not os.path.lexists(abs_ws):
        return 0

    if not os.path.isdir(abs_ws):
        return _remove_file_with_readonly_retry(abs_ws)

    reclaimed = _remove_dir_recursive_no_follow(abs_ws)
    try:
        os.rmdir(abs_ws)
    except PermissionError:
        os.chmod(abs_ws, stat.S_IRWXU)
        os.rmdir(abs_ws)
    return reclaimed


def _validate_docker_mount_path(path: str, label: str) -> str:
    _validate_no_control_chars(path, label)
    real_path = os.path.realpath(path)
    tail = real_path[2:] if _WINDOWS_DRIVE_PREFIX_RE.match(real_path) else real_path
    if ":" in tail:
        raise HostileRepoError(f"{label} contains forbidden ':' character for Docker -v mount: {path}")
    return real_path


def _validate_docker_egress_host(host: str) -> str:
    if not isinstance(host, str):
        raise HostileRepoError("allow_egress_hosts entries must be strings")
    _validate_no_control_chars(host, "allow_egress_host")
    cleaned = host.strip(" ")
    if not cleaned:
        raise HostileRepoError("allow_egress_hosts cannot contain blank entries")
    if any(ch.isspace() or ch in (",", ";", "|", "&", "$", "`", "'", '"', "\\", "/") for ch in cleaned):
        raise HostileRepoError(f"Invalid characters in egress host: {cleaned}")
    if cleaned.startswith("-"):
        raise HostileRepoError(f"Egress host cannot start with '-': {cleaned}")

    lower = cleaned.lower()
    if lower in _CLOUD_METADATA_HOSTS:
        raise HostileRepoError(f"Cloud metadata endpoint forbidden in allow_egress_hosts: {cleaned}")

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        if not _HOSTNAME_RE.match(cleaned):
            raise HostileRepoError(f"Invalid egress hostname: {cleaned}")
        return cleaned

    if ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_multicast:
        raise HostileRepoError(f"Forbidden special-use IP in allow_egress_hosts: {cleaned}")
    return str(ip_obj)


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
    real_repo = _validate_docker_mount_path(repo_path, "repo_path")
    real_out = _validate_docker_mount_path(output_dir, "output_dir")
    _validate_no_control_chars(image, "image")
    if any(ch.isspace() for ch in image) or image.startswith("-") or not _DOCKER_IMAGE_RE.match(image):
        raise HostileRepoError(f"Invalid Docker image reference: {image}")

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
    if allow_egress_hosts is not None:
        for host in allow_egress_hosts:
            clean_hosts.append(_validate_docker_egress_host(host))

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
        if not isinstance(item, str):
            raise HostileRepoError("cli_args entries must be strings")
        _validate_no_control_chars(item, "cli_arg")
        argv.append(item)

    return argv
