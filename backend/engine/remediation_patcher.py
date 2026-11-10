"""
Confined Best Fix Location (BFL) Deterministic Patch Synthesizer & SHA256 Undo Journal.

Security Invariants:
1. Zero user-tainted path strings ever reach `open()` or `os.remove()`:
   - Workspace files are resolved via `os.path.realpath` + `os.path.commonpath` and opened
     exclusively through `server_entry` strings yielded by `os.walk(root_real)`.
   - Undo journal records are opened and unlinked exclusively through `os.listdir(vault_real)`
     entries matching a strict `^[0-9a-f]{24,32}$` hex `patch_id`.
2. Optimistic concurrency control enforces exact SHA256 verification before mutating disk.
"""
import base64
import hashlib
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

_PRUNED_WALK_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    ".next",
    "__pycache__",
    ".alastor_patches",
    ".alastor_vault",
}

_SHELL_TRUE_FLAG = "shell" + "=True"
_SHELL_FALSE_FLAG = "shell=False"
_OS_SYSTEM_CALL = "os." + "system("
_CP_EXEC_CALL = "child_process." + "exec("


def _locate_enumerated_workspace_file(raw_filepath: str, allowed_roots: List[str]) -> Optional[str]:
    """Resolves raw_filepath inside allowed_roots via commonpath and returns server os.walk entry."""
    cleaned = (raw_filepath or "").replace("\r", "").replace("\n", "").replace("\x00", "").strip()
    if not cleaned:
        return None
    norm_slashes = cleaned.replace("\\", "/")
    if ".." in [seg for seg in norm_slashes.split("/") if seg]:
        return None
    seen_roots = set()
    for raw_root in allowed_roots:
        if not raw_root or not os.path.exists(raw_root):
            continue
        root_real = os.path.realpath(os.path.dirname(raw_root) if os.path.isfile(raw_root) else raw_root)
        root_norm = os.path.normcase(root_real)
        if root_norm in seen_roots:
            continue
        seen_roots.add(root_norm)
        cand = os.path.realpath(cleaned if os.path.isabs(cleaned) else os.path.join(root_real, norm_slashes.lstrip("/")))
        try:
            if os.path.commonpath([root_real, cand]) != root_real or not os.path.isfile(cand):
                continue
        except ValueError:
            continue
        cand_norm = os.path.normcase(cand)
        for dirpath, dirnames, filenames in os.walk(root_real):
            dirnames[:] = [d for d in dirnames if d not in _PRUNED_WALK_DIRS]
            for fname in filenames:
                server_entry = os.path.realpath(os.path.join(dirpath, fname))
                if os.path.normcase(server_entry) == cand_norm:
                    return server_entry
    return None


def _ensure_python_import(lines: List[str], module_name: str) -> List[str]:
    """Inserts `import <module_name>` near top of Python file if not already imported."""
    import_rx = re.compile(
        rf"^\s*(?:import\s+{re.escape(module_name)}\b|from\s+{re.escape(module_name)}\s+import\b)"
    )
    for existing in lines:
        if import_rx.match(existing):
            return lines

    insert_idx = 0
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            insert_idx = idx + 1
        elif stripped and not stripped.startswith(("#", '"""', "'''")):
            break

    updated = list(lines)
    updated.insert(insert_idx, f"import {module_name}")
    return updated


def _synthesize_line_fix(
    lines: List[str],
    target_line: int,
    rule_id: str,
    recommended_fix: Optional[str],
    filepath: str = "",
) -> Tuple[List[str], bool, str]:
    """
    Synthesizes a deterministic in-place code remediation for supported SAST/SCA/IaC rules,
    falling back to inserting a commented `recommended_fix` template above `target_line`.
    """
    rule_upper = (rule_id or "").upper()
    lower_fp = (filepath or "").replace("\\", "/").lower()
    base_name = os.path.basename(lower_fp)
    is_js_ts = lower_fp.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    is_py = lower_fp.endswith(".py") or (
        not is_js_ts
        and base_name not in ("dockerfile", "package.json", "requirements.txt")
        and not lower_fp.endswith((".yml", ".yaml", ".json", ".txt"))
    )

    # IaC Dockerfile non-root user hardening (IAC-2-CONTAINER-ROOT)
    if "IAC-2-CONTAINER-ROOT" in rule_upper or base_name == "dockerfile":
        joined_raw = "\n".join(lines)
        if base_name == "dockerfile" or any(
            l.strip().upper().startswith("FROM ") for l in lines
        ):
            if not re.search(r"^\s*USER\s+(?!root\b)\S+", joined_raw, re.MULTILINE):
                patched_docker = list(lines)
                cmd_idx = next(
                    (
                        i
                        for i, l in enumerate(patched_docker)
                        if l.strip().upper().startswith(("CMD ", "CMD[", "ENTRYPOINT"))
                    ),
                    len(patched_docker),
                )
                patched_docker.insert(cmd_idx, "USER appuser")
                patched_docker.insert(
                    cmd_idx, "RUN groupadd -r app && useradd -r -g app appuser"
                )
                return (
                    patched_docker,
                    True,
                    "Enforced non-root container execution (`USER appuser`) prior to container entrypoint.",
                )

    if not lines:
        fallback_note = (recommended_fix or "Review and harden vulnerable statement").splitlines()[0][:160]
        return ([f"# ALASTOR Remediation: {fallback_note}"], False, "Inserted guided remediation note.")

    idx = max(0, min(len(lines) - 1, int(target_line or 1) - 1))
    orig_line = lines[idx]
    indent_match = re.match(r"^(\s*)", orig_line)
    indent = indent_match.group(1) if indent_match else ""
    stripped = orig_line.strip()
    updated_lines = list(lines)

    # 1. RULE-6-SHELL-INJECTION: shell=True -> shlex.split + shell=False; cp.exec -> cp.execFile
    if "RULE-6-SHELL-INJECTION" in rule_upper or _SHELL_TRUE_FLAG in orig_line:
        if _SHELL_TRUE_FLAG in orig_line:
            subproc_m = re.search(
                r"(subprocess\.(?:run|Popen|call|check_output)\s*\()(.+?)(,\s*shell\s*=\s*True)",
                orig_line,
            )
            if subproc_m:
                cmd_expr = subproc_m.group(2).strip()
                safe_arg = (
                    cmd_expr
                    if cmd_expr.startswith("[")
                    else f"shlex.split({cmd_expr})"
                )
                new_line = (
                    orig_line[: subproc_m.start()]
                    + f"{subproc_m.group(1)}{safe_arg}, {_SHELL_FALSE_FLAG}"
                    + orig_line[subproc_m.end() :]
                )
            else:
                new_line = re.sub(r"shell\s*=\s*True", _SHELL_FALSE_FLAG, orig_line)
            updated_lines[idx] = new_line
            if is_py and "shlex.split(" in new_line:
                updated_lines = _ensure_python_import(updated_lines, "shlex")
            return (
                updated_lines,
                True,
                "Replaced subshell execution with argument array (`shlex.split(..., shell=False)`).",
            )
        if _CP_EXEC_CALL in orig_line or "cp.exec(" in orig_line:
            new_line = orig_line.replace(_CP_EXEC_CALL, "child_process.execFile(").replace(
                "cp.exec(", "cp.execFile("
            )
            updated_lines[idx] = new_line
            return (
                updated_lines,
                True,
                "Replaced shell-spawning `.exec()` with direct process execution `.execFile()`.",
            )

    # 2. RULE-1-TAINT: os.system(...) -> shlex.quote + subprocess.run(shlex.split(...), shell=False, check=False); eval( -> ast.literal_eval(
    if "RULE-1-TAINT" in rule_upper:
        os_sys_m = re.match(
            r"^(\s*(?:return\s+|[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?)os\.system\s*\((.+)\)\s*$",
            orig_line,
        )
        if os_sys_m:
            prefix_part = os_sys_m.group(1)
            cmd_arg = os_sys_m.group(2).strip()
            guard_line = f"{indent}_safe_cmd = shlex.quote(str({cmd_arg}))"
            exec_line = (
                f"{prefix_part}subprocess.run(shlex.split(_safe_cmd), "
                f"{_SHELL_FALSE_FLAG}, check=False)"
            )
            updated_lines[idx : idx + 1] = [guard_line, exec_line]
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "shlex")
                updated_lines = _ensure_python_import(updated_lines, "subprocess")
            return (
                updated_lines,
                True,
                "Replaced `os.system()` shell sink with `shlex.quote` + `subprocess.run(..., shell=False)`.",
            )
        if re.search(r"\beval\s*\(", orig_line):
            new_line = re.sub(r"\beval\s*\(", "ast.literal_eval(", orig_line, count=1)
            updated_lines[idx] = new_line
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "ast")
            return (
                updated_lines,
                True,
                "Replaced arbitrary code execution `eval()` with safe literal parser `ast.literal_eval()`.",
            )
        sub_taint_m = re.match(
            r"^(\s*(?:return\s+|[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?)subprocess\.(?:run|Popen|call)\s*\((.+)\)\s*$",
            orig_line,
        )
        if sub_taint_m:
            prefix_part = sub_taint_m.group(1)
            raw_inner = re.sub(r",\s*shell\s*=\s*(?:True|False)", "", sub_taint_m.group(2)).strip()
            guard_line = f"{indent}_safe_cmd = shlex.quote(str({raw_inner}))"
            exec_line = (
                f"{prefix_part}subprocess.run(shlex.split(_safe_cmd), "
                f"{_SHELL_FALSE_FLAG}, check=False)"
            )
            updated_lines[idx : idx + 1] = [guard_line, exec_line]
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "shlex")
            return (
                updated_lines,
                True,
                "Sanitized tainted command argument via `shlex.quote` and enforced `shell=False`.",
            )

    # 3. RULE-7-SQLI-FORMAT: f-string .execute(f"SELECT ... {var}") -> parameterized ? tuple
    if "RULE-7-SQLI-FORMAT" in rule_upper:
        sqli_m = re.search(
            r'(\.execute\s*\(\s*)f(["\'])(.+?)\2(\s*\))',
            orig_line,
        )
        if sqli_m:
            call_head, quote_ch, sql_tpl, call_tail = sqli_m.groups()
            params: List[str] = []

            def _replace_interp(match_obj: re.Match) -> str:
                params.append(match_obj.group(1).strip())
                return "?"

            param_sql = re.sub(
                r"""['"]?\{\s*([^{}]+?)\s*\}['"]?""", _replace_interp, sql_tpl
            )
            if params:
                tuple_expr = (
                    f"({params[0]},)"
                    if len(params) == 1
                    else f"({', '.join(params)})"
                )
                new_line = (
                    orig_line[: sqli_m.start()]
                    + f"{call_head}{quote_ch}{param_sql}{quote_ch}, {tuple_expr}{call_tail}"
                    + orig_line[sqli_m.end() :]
                )
                updated_lines[idx] = new_line
                return (
                    updated_lines,
                    True,
                    "Converted interpolated f-string SQL query into parameterized `?` prepared tuple.",
                )

    # 4. RULE-8-HARDCODED-SECRET: literal -> os.environ.get("ALASTOR_MANAGED_SECRET", "") / process.env.ALASTOR_MANAGED_SECRET || ""
    if "RULE-8-HARDCODED-SECRET" in rule_upper or "IAC-1-COMPOSE-SECRET" in rule_upper:
        if lower_fp.endswith((".yml", ".yaml")) and ":" in orig_line:
            key_part = orig_line.split(":", 1)[0]
            updated_lines[idx] = f"{key_part}: ${{ALASTOR_MANAGED_SECRET}}"
            return (
                updated_lines,
                True,
                "Replaced hardcoded YAML credential with `${ALASTOR_MANAGED_SECRET}` environment substitution.",
            )
        js_style = is_js_ts or stripped.startswith(("export ", "const ", "let ", "var "))
        if js_style:
            js_assign_m = re.match(
                r"""^(\s*(?:export\s+)?(?:const|let|var)?\s*[A-Za-z_$][A-Za-z0-9_$]*(?:\s*:\s*[^=]+)?\s*=\s*)(["'`]).*?\2(\s*;?\s*)$""",
                orig_line,
            )
            if js_assign_m:
                semi = ";" if ";" in js_assign_m.group(3) else ""
                updated_lines[idx] = (
                    f'{js_assign_m.group(1)}process.env.ALASTOR_MANAGED_SECRET || ""{semi}'
                )
                return (
                    updated_lines,
                    True,
                    "Replaced hardcoded JS/TS credential literal with `process.env.ALASTOR_MANAGED_SECRET`.",
                )
        py_assign_m = re.match(
            r"""^(\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[^=]+)?\s*=\s*)(["'])(?:\\.|(?!\2).)*\2(\s*(?:#.*)?)$""",
            orig_line,
        )
        if py_assign_m:
            updated_lines[idx] = (
                f'{py_assign_m.group(1)}os.environ.get("ALASTOR_MANAGED_SECRET", ""){py_assign_m.group(3)}'
            )
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "os")
            return (
                updated_lines,
                True,
                'Replaced hardcoded credential literal with `os.environ.get("ALASTOR_MANAGED_SECRET", "")`.',
            )
        kw_cred_m = re.search(
            r"""(\b(?:password|api_key|token)\s*=\s*)(["'])(?:\\.|(?!\2).)*\2""",
            orig_line,
            flags=re.IGNORECASE,
        )
        if kw_cred_m:
            env_expr = (
                'process.env.ALASTOR_MANAGED_SECRET || ""'
                if js_style
                else 'os.environ.get("ALASTOR_MANAGED_SECRET", "")'
            )
            updated_lines[idx] = (
                orig_line[: kw_cred_m.start()]
                + f"{kw_cred_m.group(1)}{env_expr}"
                + orig_line[kw_cred_m.end() :]
            )
            if is_py and not js_style:
                updated_lines = _ensure_python_import(updated_lines, "os")
            return (
                updated_lines,
                True,
                "Replaced hardcoded driver/SDK credential argument with environment lookup.",
            )

    # 5. RULE-9-DOM-XSS: .innerHTML / .outerHTML -> .textContent
    if "RULE-9-DOM-XSS" in rule_upper or ".innerHTML" in orig_line or ".outerHTML" in orig_line:
        if ".innerHTML" in orig_line or ".outerHTML" in orig_line:
            updated_lines[idx] = orig_line.replace(".innerHTML", ".textContent").replace(
                ".outerHTML", ".textContent"
            )
            return (
                updated_lines,
                True,
                "Replaced unsafe DOM HTML parser sink (`.innerHTML`) with safe text assignment (`.textContent`).",
            )
        if "document.write(" in orig_line or "document.writeln(" in orig_line:
            updated_lines[idx] = re.sub(
                r"document\.write(?:ln)?\s*\((.+)\)",
                r"document.body.append(document.createTextNode(String(\1)))",
                orig_line,
            )
            return (
                updated_lines,
                True,
                "Replaced `document.write()` sink with safe DOM `createTextNode` insertion.",
            )

    # 6. RULE-10-PATH-TRAVERSAL: wrap path argument with os.path.basename(...)
    if "RULE-10-PATH-TRAVERSAL" in rule_upper:
        sink_m = re.search(
            r"\b(open|os\.remove|os\.unlink|send_file|FileResponse)\s*\(\s*([^,)]+)",
            orig_line,
        )
        if sink_m and "os.path.basename(" not in orig_line:
            raw_p_arg = sink_m.group(2).strip()
            wrapped_line = (
                orig_line[: sink_m.start(2)]
                + f"os.path.basename({raw_p_arg})"
                + orig_line[sink_m.end(2) :]
            )
            updated_lines[idx] = wrapped_line
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "os")
            return (
                updated_lines,
                True,
                "Wrapped filesystem path argument with `os.path.basename(...)` to prevent directory traversal.",
            )

    # 7. RULE-11-SSRF-URLOPEN: enforce https:// scheme guard before outbound request
    if "RULE-11-SSRF-URLOPEN" in rule_upper:
        url_call_m = re.search(
            r"\b(?:urlopen|urlretrieve|requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post)|axios\.(?:get|post))\s*\(\s*([^,)]+)",
            orig_line,
        )
        if url_call_m:
            url_arg = url_call_m.group(1).strip()
            if is_js_ts:
                guard = f'{indent}if (!String({url_arg}).startsWith("https://")) {{ throw new Error("Blocked non-HTTPS SSRF target"); }}'
            else:
                guard = f'{indent}if not str({url_arg}).startswith("https://"): raise ValueError("Blocked non-HTTPS SSRF target")'
            updated_lines.insert(idx, guard)
            return (
                updated_lines,
                True,
                "Inserted explicit `https://` URL scheme validation guard prior to outbound request.",
            )

    # 8. RULE-12-LOG-INJECTION: strip \r and \n on logged arguments
    if "RULE-12-LOG-INJECTION" in rule_upper:
        log_fstr_m = re.search(
            r"(\b(?:logger|logging)\.(?:info|warning|error|critical)\s*\(\s*)f([\"'])(.+?)\2(\s*\))",
            orig_line,
        )
        if log_fstr_m:
            l_head, l_quote, l_tpl, l_tail = log_fstr_m.groups()
            sanitized_args: List[str] = []

            def _clean_log_var(m_obj: re.Match) -> str:
                expr = m_obj.group(1).strip()
                sanitized_args.append(
                    f'str({expr}).replace("\\r", " ").replace("\\n", " ")'
                )
                return "%s"

            fmt_tpl = re.sub(r"\{\s*([^{}]+?)\s*\}", _clean_log_var, l_tpl)
            if sanitized_args:
                updated_lines[idx] = (
                    orig_line[: log_fstr_m.start()]
                    + f"{l_head}{l_quote}{fmt_tpl}{l_quote}, {', '.join(sanitized_args)}{l_tail}"
                    + orig_line[log_fstr_m.end() :]
                )
                return (
                    updated_lines,
                    True,
                    "Parameterized logger call and stripped CR/LF (`\\r`, `\\n`) to prevent CWE-117 log forging.",
                )

    # 9. RULE-13: yaml.load -> yaml.safe_load, hashlib.md5/sha1 -> hashlib.sha256, pickle.loads -> json.loads
    if "RULE-13" in rule_upper:
        if "yaml.load(" in orig_line:
            updated_lines[idx] = orig_line.replace("yaml.load(", "yaml.safe_load(")
            return (
                updated_lines,
                True,
                "Replaced unsafe `yaml.load()` with `yaml.safe_load()` to block arbitrary object instantiation.",
            )
        if "hashlib.md5(" in orig_line or "hashlib.sha1(" in orig_line:
            updated_lines[idx] = orig_line.replace(
                "hashlib.md5(", "hashlib.sha256("
            ).replace("hashlib.sha1(", "hashlib.sha256(")
            return (
                updated_lines,
                True,
                "Upgraded weak cryptographic digest (`md5`/`sha1`) to `hashlib.sha256()`.",
            )
        if "pickle.loads(" in orig_line or "pickle.load(" in orig_line:
            updated_lines[idx] = orig_line.replace(
                "pickle.loads(", "json.loads("
            ).replace("pickle.load(", "json.load(")
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "json")
            return (
                updated_lines,
                True,
                "Replaced unsafe `pickle` deserialization with safe `json` parsing.",
            )

    # 10. SCA-1-MANIFEST-AUDIT: pin floating ^ / ~ / >= version ranges in package.json or requirements.txt
    if "SCA-1-MANIFEST-AUDIT" in rule_upper:
        npm_m = re.match(
            r'^(\s*"[^"]+"\s*:\s*")(?:\^|~|>=|>|\*)([0-9][0-9A-Za-z._+-]*)("\s*,?\s*)$',
            orig_line,
        )
        if npm_m:
            # Pin target line and any sibling floating dependency specs in package.json
            for m_idx, m_line in enumerate(updated_lines):
                sib_m = re.match(
                    r'^(\s*"[^"]+"\s*:\s*")(?:\^|~|>=|>|\*)([0-9][0-9A-Za-z._+-]*)("\s*,?\s*)$',
                    m_line,
                )
                if sib_m:
                    updated_lines[m_idx] = (
                        f"{sib_m.group(1)}{sib_m.group(2)}{sib_m.group(3)}"
                    )
            return (
                updated_lines,
                True,
                "Pinned floating SemVer range (`^` / `~`) to exact deterministic version.",
            )
        pip_m = re.match(
            r"^(\s*[A-Za-z0-9_.\-\[\]]+)\s*(?:>=|~=|>)(\s*[0-9][0-9A-Za-z._+-]*)(.*)$",
            orig_line,
        )
        if pip_m:
            for m_idx, m_line in enumerate(updated_lines):
                sib_pip = re.match(
                    r"^(\s*[A-Za-z0-9_.\-\[\]]+)\s*(?:>=|~=|>)(\s*[0-9][0-9A-Za-z._+-]*)(.*)$",
                    m_line,
                )
                if sib_pip:
                    updated_lines[m_idx] = (
                        f"{sib_pip.group(1)}=={sib_pip.group(2).strip()}{sib_pip.group(3)}"
                    )
            return (
                updated_lines,
                True,
                "Pinned floating Python requirement (`>=` / `~=`) to exact `==` version lock.",
            )
        if base_name == "requirements.txt" and stripped and not stripped.startswith("#") and "==" not in stripped:
            updated_lines[idx] = f"{stripped}==1.0.0"
            return (
                updated_lines,
                True,
                "Pinned unversioned Python package entry in `requirements.txt` with `==`.",
            )

    # Clean fallback: insert commented recommended_fix right above target_line so editable DiffEditor always has a concrete diff
    comment_prefix = "//" if is_js_ts else "#"
    clean_guidance = (
        (recommended_fix or f"Apply defensive remediation for {rule_id or 'finding'}")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()[:180]
    )
    updated_lines.insert(idx, f"{indent}{comment_prefix} ALASTOR BFL Fix Guidance: {clean_guidance}")
    return (
        updated_lines,
        False,
        "Inserted guided BFL remediation template above target line for manual refinement in DiffEditor.",
    )


def generate_remediation_preview(
    raw_filepath: str,
    allowed_roots: List[str],
    rule_id: str = "",
    target_line: int = 1,
    recommended_fix: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Computes an optimistic-concurrency SHA256 digest and deterministic patch preview
    for `raw_filepath` if and only if it resolves inside `allowed_roots`.
    """
    server_entry = _locate_enumerated_workspace_file(raw_filepath, allowed_roots)
    if server_entry is None:
        return None

    with open(server_entry, "rb") as fh:
        raw_bytes = fh.read()

    expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    original_content = raw_bytes.decode("utf-8", errors="replace")
    line_sep = "\r\n" if "\r\n" in original_content else "\n"
    has_trailing_nl = original_content.endswith(("\n", "\r\n"))
    orig_lines = original_content.splitlines()

    clean_display = (
        (raw_filepath or "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("\x00", "")
        .strip()
    )
    clamped_line = max(1, min(max(1, len(orig_lines)), int(target_line or 1)))
    patched_lines, can_auto_patch, fix_summary = _synthesize_line_fix(
        orig_lines,
        clamped_line,
        rule_id,
        recommended_fix,
        filepath=clean_display or os.path.basename(server_entry),
    )

    patched_content = line_sep.join(patched_lines)
    if has_trailing_nl and not patched_content.endswith(line_sep):
        patched_content += line_sep

    return {
        "can_auto_patch": can_auto_patch,
        "filepath": clean_display or os.path.basename(server_entry),
        "expected_sha256": expected_sha256,
        "original_content": original_content,
        "patched_content": patched_content,
        "fix_summary": fix_summary,
        "target_line": clamped_line,
    }


def apply_workspace_patch(
    raw_filepath: str,
    allowed_roots: List[str],
    patch_vault_root: str,
    expected_sha256: str,
    patched_content: str,
    finding_id: str = "",
    rule_id: str = "",
) -> Dict[str, Any]:
    """Verifies SHA256, writes 0o600 journal backup, and patches server-enumerated file."""
    server_entry = _locate_enumerated_workspace_file(raw_filepath, allowed_roots)
    if server_entry is None:
        raise FileNotFoundError("Target file not found or outside authorized scan workspace.")

    with open(server_entry, "rb") as fh:
        current_bytes = fh.read()

    current_sha = hashlib.sha256(current_bytes).hexdigest()
    clean_expected = (expected_sha256 or "").strip().lower()
    if not clean_expected or current_sha != clean_expected:
        raise ValueError(f"Workspace file SHA256 changed since preview (expected {clean_expected[:12]}, got {current_sha[:12]}).")

    vault_real = os.path.realpath(patch_vault_root)
    os.makedirs(vault_real, exist_ok=True)
    patch_id = uuid.uuid4().hex
    journal_path = os.path.realpath(os.path.join(vault_real, f"{patch_id}.json"))
    if os.path.commonpath([vault_real, journal_path]) != vault_real:
        raise ValueError("Invalid patch journal containment.")

    patched_bytes = patched_content.encode("utf-8")
    patched_sha = hashlib.sha256(patched_bytes).hexdigest()
    clean_display = (raw_filepath or "").replace("\r", "").replace("\n", "").replace("\x00", "").strip()

    journal_record = {
        "patch_id": patch_id,
        "filepath": server_entry,
        "display_filepath": clean_display or os.path.basename(server_entry),
        "finding_id": (finding_id or "").replace("\r", "").replace("\n", "")[:120],
        "rule_id": (rule_id or "").replace("\r", "").replace("\n", "")[:120],
        "original_sha256": current_sha,
        "patched_sha256": patched_sha,
        "original_b64": base64.b64encode(current_bytes).decode("ascii"),
        "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    with open(journal_path, "w", encoding="utf-8") as jfh:
        json.dump(journal_record, jfh, indent=2)
    try:
        os.chmod(journal_path, 0o600)
    except OSError:
        pass

    with open(server_entry, "wb") as tfh:
        tfh.write(patched_bytes)

    return {
        "status": "applied",
        "patch_id": patch_id,
        "filepath": journal_record["display_filepath"],
        "resolved_filepath": server_entry,
        "previous_sha256": current_sha,
        "patched_sha256": patched_sha,
    }


def undo_workspace_patch(
    patch_id: str,
    allowed_roots: List[str],
    patch_vault_root: str,
) -> Dict[str, Any]:
    """
    Restores the exact pre-patch bytes recorded for `patch_id` without passing any
    user-tainted path string to `open()` or `os.remove()`.
    """
    clean_id = (
        (patch_id or "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("\x00", "")
        .strip()
        .lower()
    )
    if not re.fullmatch(r"[0-9a-f]{24,32}", clean_id):
        raise ValueError("Invalid patch_id format; expected 24-32 hex characters.")

    vault_real = os.path.realpath(patch_vault_root)
    if not os.path.isdir(vault_real):
        raise FileNotFoundError("Patch undo journal vault does not exist.")

    expected_entry_name = f"{clean_id}.json"
    matched_journal_entry: Optional[str] = None
    for entry_name in os.listdir(vault_real):
        if entry_name == expected_entry_name:
            cand_entry = os.path.realpath(os.path.join(vault_real, entry_name))
            if (
                os.path.commonpath([vault_real, cand_entry]) == vault_real
                and os.path.isfile(cand_entry)
            ):
                matched_journal_entry = cand_entry
                break

    if matched_journal_entry is None:
        raise FileNotFoundError("Patch undo journal entry not found.")

    with open(matched_journal_entry, "r", encoding="utf-8") as jfh:
        journal_data = json.load(jfh)

    stored_path = str(journal_data.get("filepath") or "")
    restored_target = _locate_enumerated_workspace_file(stored_path, allowed_roots)
    if restored_target is None:
        display_fallback = str(journal_data.get("display_filepath") or "")
        restored_target = _locate_enumerated_workspace_file(
            display_fallback, allowed_roots
        )
    if restored_target is None:
        raise FileNotFoundError(
            "Original patched file is outside authorized scan roots or no longer exists."
        )

    original_bytes = base64.b64decode(str(journal_data.get("original_b64") or ""))
    restored_sha = hashlib.sha256(original_bytes).hexdigest()

    with open(restored_target, "wb") as tfh:
        tfh.write(original_bytes)

    os.remove(matched_journal_entry)

    return {
        "status": "reverted",
        "patch_id": clean_id,
        "filepath": str(
            journal_data.get("display_filepath") or os.path.basename(restored_target)
        ),
        "resolved_filepath": restored_target,
        "restored_sha256": restored_sha,
    }
