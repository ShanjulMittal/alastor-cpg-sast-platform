"""
ALASTOR v5.1 — Mediated-Egress Dual Docker Sandbox Orchestrator.

Provides:
1. Strict FQDN allowlist validation (`validate_mediated_llm_host`) for LLM API domains
   only (rejecting wildcards, leading dots, IPs, metadata endpoints, and injection).
2. Deny-by-default Squid CONNECT:443 config synthesis (`generate_squid_egress_config`).
3. Single- (`egress_mode="none"`) and dual-container Unix-socket-bridged
   (`egress_mode="mediated"`, scanner STILL runs `--network=none`!) execution plan
   generation (`build_mediated_sandbox_plan`).
4. Local Docker image presence and `org.alastor.version` drift inspection
   (`inspect_sandbox_images`) with graceful degradation when Docker is absent/stopped.
"""
from __future__ import annotations

import inspect
import ipaddress
import os
import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from engine.hostile_repo_guard import (
    HostileRepoError,
    _CLOUD_METADATA_HOSTS,
    _validate_docker_mount_path,
    _validate_no_control_chars,
    build_sandbox_docker_command,
    is_link_or_junction,
)
from models import (
    SandboxExecutionPlan,
    SandboxImageInfo,
    SandboxImageStatus,
    SandboxPlanRequest,
)

ALASTOR_SANDBOX_VERSION = "5.1.0"
SANDBOX_IMAGE_NAME = "alastor-sandbox:local"
EGRESS_IMAGE_NAME = "alastor-egress:local"

_FQDN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_NUMERIC_OR_HEX_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")
_DISALLOWED_HOST_SUFFIXES: Tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".arpa",
    ".lan",
    ".home",
    ".intranet",
    ".private",
)
_FORBIDDEN_HOST_CHARS = frozenset({"*", "/", ":", ";", "#", "@", "\\", "?", "&", "=", "%"})


def validate_mediated_llm_host(host: str) -> str:
    """
    Validate and normalize a public LLM API DNS FQDN for Squid `CONNECT 443` egress.
    Rejects control chars, whitespace, wildcards, leading dots/hyphens, IP literals,
    cloud metadata names, and `.local`/`.internal`/`.localhost` hostnames.
    """
    if not isinstance(host, str):
        raise HostileRepoError("Allowed LLM host must be a string")
    _validate_no_control_chars(host, "allowed_llm_host")

    cleaned = host.strip(" ").lower()
    if not cleaned:
        raise HostileRepoError("Allowed LLM host cannot be blank")
    if any(ch.isspace() for ch in cleaned):
        raise HostileRepoError(f"Allowed LLM host cannot contain whitespace: {host}")
    if cleaned.startswith("-") or cleaned.startswith("."):
        raise HostileRepoError(f"Allowed LLM host cannot start with '-' or '.': {host}")
    if any(ch in _FORBIDDEN_HOST_CHARS for ch in cleaned):
        raise HostileRepoError(f"Forbidden character in allowed LLM host: {host}")

    if cleaned in _CLOUD_METADATA_HOSTS or cleaned == "localhost":
        raise HostileRepoError(f"Disallowed internal/metadata host: {host}")
    if cleaned.endswith(_DISALLOWED_HOST_SUFFIXES):
        raise HostileRepoError(f"Disallowed local/internal DNS suffix in host: {host}")

    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    else:
        raise HostileRepoError(
            f"IP literals are forbidden in mediated LLM egress allowlist: {host}"
        )

    if len(cleaned) > 253 or not _FQDN_RE.match(cleaned):
        raise HostileRepoError(f"Invalid public DNS FQDN for mediated LLM host: {host}")

    labels = cleaned.split(".")
    if labels[-1].isdigit() or all(_NUMERIC_OR_HEX_LABEL_RE.match(lbl) for lbl in labels):
        raise HostileRepoError(
            f"Numeric/encoded IP hostnames are forbidden in mediated LLM egress allowlist: {host}"
        )

    return cleaned


def _dedupe_validated_llm_hosts(allowed_llm_hosts: Sequence[str]) -> List[str]:
    if not isinstance(allowed_llm_hosts, (list, tuple, set)) or not allowed_llm_hosts:
        raise HostileRepoError(
            "allowed_llm_hosts must be a non-empty list of validated public LLM API hostnames"
        )
    deduped: List[str] = []
    seen = set()
    for raw_host in allowed_llm_hosts:
        clean_host = validate_mediated_llm_host(raw_host)
        if clean_host not in seen:
            seen.add(clean_host)
            deduped.append(clean_host)
    if not deduped:
        raise HostileRepoError("allowed_llm_hosts cannot be empty")
    return deduped


def generate_squid_egress_config(allowed_llm_hosts: Sequence[str], port: int = 3128) -> str:
    """
    Generate a minimal, deny-by-default Squid configuration permitting HTTPS `CONNECT`
    exclusively to port `443` on explicitly validated public LLM API hostnames.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not (1024 <= port <= 65535):
        raise HostileRepoError(f"Squid proxy port must be an integer in 1024..65535, got: {port!r}")

    clean_hosts = _dedupe_validated_llm_hosts(allowed_llm_hosts)
    lines = [
        f"http_port 127.0.0.1:{port}",
        "acl SSL_ports port 443",
        "acl CONNECT method CONNECT",
        (
            "acl blocked_dst dst 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 "
            "192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 ::1 fc00::/7 fe80::/10"
        ),
        f"acl allowed_llm dstdomain {' '.join(clean_hosts)}",
        "http_access deny !CONNECT",
        "http_access deny !SSL_ports",
        "http_access deny blocked_dst",
        "http_access allow CONNECT SSL_ports allowed_llm",
        "http_access deny all",
        "cache deny all",
        "access_log none",
        "cache_log /dev/null",
        "pid_filename /tmp/squid.pid",
        "pinger_enable off",
        "netdb_filename none",
        "coredump_dir /tmp",
    ]
    return "\n".join(lines) + "\n"


def _resolve_confined_mount_child(base_real: str, *parts: str, label: str) -> str:
    """Resolve `base_real / *parts` ensuring no symlink/junction or commonpath escape."""
    norm_base = os.path.normcase(base_real)
    cursor = base_real
    for part in parts:
        cursor = os.path.join(cursor, part)
        if is_link_or_junction(cursor):
            raise HostileRepoError(
                f"Refusing symlink/junction in {label} mount path: {cursor}"
            )
    real_child = _validate_docker_mount_path(cursor, label)
    try:
        if os.path.commonpath([norm_base, os.path.normcase(real_child)]) != norm_base:
            raise HostileRepoError(
                f"Refusing {label} mount path escaping confined directory: {cursor}"
            )
    except ValueError as exc:
        raise HostileRepoError(
            f"Refusing {label} mount path escaping confined directory: {cursor}"
        ) from exc
    return real_child


def build_mediated_sandbox_plan(req: SandboxPlanRequest) -> SandboxExecutionPlan:
    """
    Build a hardened single-container (`egress_mode="none"`) or dual-container
    Unix-socket-bridged (`egress_mode="mediated"`) Docker sandbox execution plan.
    The scanner container ALWAYS runs with `--network=none`.
    """
    if req.egress_mode not in ("none", "mediated"):
        raise HostileRepoError(f"Unsupported sandbox egress_mode: {req.egress_mode!r}")

    _validate_no_control_chars(req.project_path, "project_path")
    cleaned_project = req.project_path.strip()
    if not cleaned_project or cleaned_project.startswith("-") or "://" in cleaned_project:
        raise HostileRepoError(f"Invalid project_path for sandbox plan: {req.project_path}")
    if ".." in [s for s in re.split(r"[\\/]+", cleaned_project) if s]:
        raise HostileRepoError(f"Path traversal '..' is forbidden in project_path: {req.project_path}")
    if is_link_or_junction(os.path.abspath(cleaned_project)):
        raise HostileRepoError(f"Refusing symlink/junction project_path: {req.project_path}")
    real_repo = _validate_docker_mount_path(cleaned_project, "project_path")
    if not os.path.isdir(real_repo):
        raise HostileRepoError(f"project_path does not exist or is not a directory: {req.project_path}")

    if req.output_dir is not None and req.output_dir != "":
        _validate_no_control_chars(req.output_dir, "output_dir")
        cleaned_out = req.output_dir.strip()
        if not cleaned_out or cleaned_out.startswith("-") or "://" in cleaned_out:
            raise HostileRepoError(f"Invalid output_dir for sandbox plan: {req.output_dir}")
        if ".." in [s for s in re.split(r"[\\/]+", cleaned_out) if s]:
            raise HostileRepoError(f"Path traversal '..' is forbidden in output_dir: {req.output_dir}")
        abs_out = os.path.abspath(cleaned_out)
        if is_link_or_junction(abs_out):
            raise HostileRepoError(f"Refusing symlink/junction output_dir: {req.output_dir}")
        real_out = _validate_docker_mount_path(cleaned_out, "output_dir")
        try:
            if os.path.commonpath([os.path.normcase(real_repo), os.path.normcase(abs_out)]) == os.path.normcase(real_repo):
                rel_out = os.path.relpath(abs_out, real_repo)
                if rel_out not in (".", ""):
                    real_out = _resolve_confined_mount_child(
                        real_repo, *[p for p in rel_out.split(os.sep) if p and p != "."], label="output_dir"
                    )
        except ValueError:
            pass
    else:
        real_out = _resolve_confined_mount_child(
            real_repo, ".alastor_sandbox_out", label="output_dir"
        )
    if os.path.lexists(real_out) and not os.path.isdir(real_out):
        raise HostileRepoError(f"output_dir exists and is not a directory: {real_out}")

    base_scanner_cmd = build_sandbox_docker_command(
        repo_path=real_repo,
        output_dir=real_out,
        image=SANDBOX_IMAGE_NAME,
        allow_egress_hosts=None,
        cli_args=req.cli_args,
    )
    mount_idx = base_scanner_cmd.index("-v")

    build_commands = [
        (
            f"docker build -f docker/sandbox/Dockerfile "
            f"--build-arg ALASTOR_IMAGE_VERSION={ALASTOR_SANDBOX_VERSION} "
            f"-t {SANDBOX_IMAGE_NAME} ."
        ),
        (
            f"docker build -f docker/sandbox/egress.Dockerfile "
            f"--build-arg ALASTOR_IMAGE_VERSION={ALASTOR_SANDBOX_VERSION} "
            f"-t {EGRESS_IMAGE_NAME} ."
        ),
    ]

    security_invariants: List[str] = [
        "Scanner container runs with --network=none (zero direct kernel IP egress).",
        "Root filesystem mounted --read-only with bounded noexec/nosuid tmpfs /tmp.",
        "All Linux capabilities dropped (--cap-drop=ALL) and --security-opt=no-new-privileges:true enforced.",
        "Non-root UID/GID (--user 65534:65534), --pids-limit=256, and --memory=2g enforced.",
        "Target repository bind-mounted read-only (:/workspace:ro) with pinned hardened git config.",
    ]
    warnings: List[str] = []

    if req.egress_mode == "none":
        if req.allowed_llm_hosts:
            warnings.append(
                "allowed_llm_hosts ignored because egress_mode='none' enforces --network=none."
            )
        scanner_docker_cmd = (
            base_scanner_cmd[:mount_idx]
            + ["--user", "65534:65534"]
            + base_scanner_cmd[mount_idx:]
        )
        return SandboxExecutionPlan(
            egress_mode="none",
            allowed_llm_hosts=[],
            squid_config=None,
            egress_docker_cmd=None,
            scanner_docker_cmd=scanner_docker_cmd,
            build_commands=build_commands,
            security_invariants=security_invariants,
            warnings=warnings,
        )

    clean_hosts = _dedupe_validated_llm_hosts(req.allowed_llm_hosts)
    squid_config = generate_squid_egress_config(clean_hosts, port=3128)

    _ = _resolve_confined_mount_child(real_out, ".alastor_egress", label="egress_state_dir")
    squid_conf_host = _resolve_confined_mount_child(
        real_out, ".alastor_egress", "squid.conf", label="squid_conf_host"
    )
    sock_dir = _resolve_confined_mount_child(
        real_out, ".alastor_egress", "run", label="sock_dir"
    )

    egress_docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=128",
        "--memory=512m",
        "--user",
        "65534:65534",
        "-v",
        f"{squid_conf_host}:/etc/squid/squid.conf:ro",
        "-v",
        f"{sock_dir}:/run/alastor-egress:rw",
        EGRESS_IMAGE_NAME,
        "sh",
        "-c",
        "socat UNIX-LISTEN:/run/alastor-egress/proxy.sock,fork,reuseaddr,unlink-early,mode=0600 TCP:127.0.0.1:3128 & "
        "exec squid -N -f /etc/squid/squid.conf",
    ]

    warnings.append(
        f"Pre-write Squid config to '{squid_conf_host}' and create socket directory "
        f"'{sock_dir}' writable by UID 65534 before starting the egress sidecar container."
    )

    scanner_docker_cmd = (
        base_scanner_cmd[:mount_idx]
        + [
            "--user",
            "65534:65534",
            "-v",
            f"{sock_dir}:/run/alastor-egress:rw",
            "--env",
            "ALASTOR_EGRESS_SOCKET=/run/alastor-egress/proxy.sock",
            "--env",
            "HTTP_PROXY=http://127.0.0.1:3128",
            "--env",
            "HTTPS_PROXY=http://127.0.0.1:3128",
        ]
        + base_scanner_cmd[mount_idx:]
    )

    security_invariants.extend(
        [
            "Egress proxy sidecar runs --read-only, --cap-drop=ALL, --user 65534:65534 with squid.conf mounted :ro.",
            "Mediated LLM traffic traverses only shared Unix socket /run/alastor-egress/proxy.sock (mode 0600).",
            "Deny-by-default Squid ACL permits CONNECT port 443 ONLY to validated public LLM FQDNs.",
        ]
    )

    return SandboxExecutionPlan(
        egress_mode="mediated",
        allowed_llm_hosts=clean_hosts,
        squid_config=squid_config,
        egress_docker_cmd=egress_docker_cmd,
        scanner_docker_cmd=scanner_docker_cmd,
        build_commands=build_commands,
        security_invariants=security_invariants,
        warnings=warnings,
    )


def _invoke_docker_inspect(
    runner: Optional[Callable[..., Any]],
    cmd: List[str],
) -> Any:
    if runner is None:
        return subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=5,
        )
    try:
        sig = inspect.signature(runner)
        params = sig.parameters
        accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
        kwargs: Dict[str, Any] = {}
        for key, val in (
            ("shell", False),
            ("capture_output", True),
            ("text", True),
            ("stdin", subprocess.DEVNULL),
            ("timeout", 5),
        ):
            if accepts_kwargs or key in params:
                kwargs[key] = val
        return runner(cmd, **kwargs)
    except (TypeError, ValueError):
        return runner(cmd)


def _inspect_single_image(
    docker_bin: str,
    image_name: str,
    expected_version: str,
    subprocess_runner: Optional[Callable[..., Any]],
) -> Tuple[bool, SandboxImageInfo]:
    cmd = [
        docker_bin,
        "image",
        "inspect",
        "--format",
        '{{index .Config.Labels "org.alastor.version"}}',
        image_name,
    ]
    try:
        proc = _invoke_docker_inspect(subprocess_runner, cmd)
    except FileNotFoundError:
        return False, SandboxImageInfo(
            image_name=image_name,
            present=False,
            label_version=None,
            expected_version=expected_version,
            version_matches=False,
            detail="docker CLI not found on PATH.",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, SandboxImageInfo(
            image_name=image_name,
            present=False,
            label_version=None,
            expected_version=expected_version,
            version_matches=False,
            detail=f"Docker inspection unavailable: {exc}",
        )

    rc = getattr(proc, "returncode", 1)
    stdout = (getattr(proc, "stdout", "") or "").strip()
    stderr = (getattr(proc, "stderr", "") or "").strip()

    if rc == 0:
        if not stdout or stdout == "<no value>":
            return True, SandboxImageInfo(
                image_name=image_name,
                present=True,
                label_version=None,
                expected_version=expected_version,
                version_matches=False,
                detail=f"Image '{image_name}' missing org.alastor.version label (expected {expected_version}).",
            )
        matches = stdout == expected_version
        detail = (
            f"Image '{image_name}' matches expected version {expected_version}."
            if matches
            else f"Image '{image_name}' version {stdout} drifted from expected {expected_version}; rebuild required."
        )
        return True, SandboxImageInfo(
            image_name=image_name,
            present=True,
            label_version=stdout,
            expected_version=expected_version,
            version_matches=matches,
            detail=detail,
        )

    low_err = stderr.lower()
    daemon_down = (
        "cannot connect to the docker daemon" in low_err
        or "is the docker daemon running" in low_err
        or "error during connect" in low_err
        or ("daemon" in low_err and "not running" in low_err)
        or "permission denied" in low_err
    )
    if daemon_down:
        return False, SandboxImageInfo(
            image_name=image_name,
            present=False,
            label_version=None,
            expected_version=expected_version,
            version_matches=False,
            detail=f"Docker daemon unreachable: {stderr[:200]}",
        )

    return True, SandboxImageInfo(
        image_name=image_name,
        present=False,
        label_version=None,
        expected_version=expected_version,
        version_matches=False,
        detail=f"Image '{image_name}' not found locally; build from docker/sandbox/.",
    )


def inspect_sandbox_images(
    expected_version: str = ALASTOR_SANDBOX_VERSION,
    subprocess_runner: Optional[Callable[..., Any]] = None,
) -> SandboxImageStatus:
    """
    Inspect local Docker availability and `org.alastor.version` labels on
    `alastor-sandbox:local` and `alastor-egress:local`. Never raises if Docker
    CLI or daemon is missing/stopped.
    """
    docker_bin = shutil.which("docker")
    if subprocess_runner is None and docker_bin is None:
        return SandboxImageStatus(
            docker_available=False,
            expected_version=expected_version,
            sandbox_image=SandboxImageInfo(
                image_name=SANDBOX_IMAGE_NAME,
                present=False,
                label_version=None,
                expected_version=expected_version,
                version_matches=False,
                detail="docker CLI not found on PATH.",
            ),
            egress_image=SandboxImageInfo(
                image_name=EGRESS_IMAGE_NAME,
                present=False,
                label_version=None,
                expected_version=expected_version,
                version_matches=False,
                detail="docker CLI not found on PATH.",
            ),
            ready_for_none_mode=False,
            ready_for_mediated_mode=False,
        )

    eff_bin = docker_bin or "docker"
    s_avail, sandbox_info = _inspect_single_image(
        eff_bin, SANDBOX_IMAGE_NAME, expected_version, subprocess_runner
    )
    e_avail, egress_info = _inspect_single_image(
        eff_bin, EGRESS_IMAGE_NAME, expected_version, subprocess_runner
    )
    docker_available = s_avail and e_avail
    ready_none = docker_available and sandbox_info.present and sandbox_info.version_matches
    ready_mediated = ready_none and egress_info.present and egress_info.version_matches

    return SandboxImageStatus(
        docker_available=docker_available,
        expected_version=expected_version,
        sandbox_image=sandbox_info,
        egress_image=egress_info,
        ready_for_none_mode=ready_none,
        ready_for_mediated_mode=ready_mediated,
    )


__all__ = [
    "ALASTOR_SANDBOX_VERSION",
    "EGRESS_IMAGE_NAME",
    "SANDBOX_IMAGE_NAME",
    "build_mediated_sandbox_plan",
    "generate_squid_egress_config",
    "inspect_sandbox_images",
    "validate_mediated_llm_host",
]
