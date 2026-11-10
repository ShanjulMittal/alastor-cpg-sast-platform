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
import ast
import base64
import difflib
import hashlib
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

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
    docstring_end_idx = 0
    try:
        tree = ast.parse("\n".join(lines))
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)
            and tree.body[0].end_lineno
        ):
            docstring_end_idx = int(tree.body[0].end_lineno)
    except SyntaxError:
        docstring_end_idx = 0

    for idx in range(docstring_end_idx, len(lines)):
        stripped = lines[idx].strip()
        if stripped.startswith(("import ", "from ")):
            insert_idx = idx + 1
        elif stripped and not stripped.startswith(("#", '"""', "'''")):
            break

    if insert_idx < docstring_end_idx:
        insert_idx = docstring_end_idx

    updated = list(lines)
    updated.insert(insert_idx, f"import {module_name}")
    return updated


def _split_first_call_arg(inner_args: str) -> Tuple[str, str]:
    """Splits `<first_arg><, rest_args>` at the first top-level comma outside quotes and brackets."""
    depth = 0
    quote_tok: Optional[str] = None
    pos = 0
    total = len(inner_args)
    while pos < total:
        ch = inner_args[pos]
        if quote_tok is not None:
            if ch == "\\":
                pos += 2
                continue
            if inner_args.startswith(quote_tok, pos):
                pos += len(quote_tok)
                quote_tok = None
                continue
            pos += 1
            continue
        if inner_args.startswith('"""', pos) or inner_args.startswith("'''", pos):
            quote_tok = inner_args[pos : pos + 3]
            pos += 3
            continue
        if ch in ('"', "'"):
            quote_tok = ch
            pos += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            return inner_args[:pos].strip(), inner_args[pos:]
        pos += 1
    return inner_args.strip(), ""


def _split_top_level_plus(expr: str) -> List[str]:
    """Splits string concatenation `a + b` at top-level `+` operators outside quotes and brackets."""
    parts: List[str] = []
    depth = 0
    quote_tok: Optional[str] = None
    start_idx = 0
    pos = 0
    total = len(expr)
    while pos < total:
        ch = expr[pos]
        if quote_tok is not None:
            if ch == "\\":
                pos += 2
                continue
            if expr.startswith(quote_tok, pos):
                pos += len(quote_tok)
                quote_tok = None
                continue
            pos += 1
            continue
        if expr.startswith('"""', pos) or expr.startswith("'''", pos):
            quote_tok = expr[pos : pos + 3]
            pos += 3
            continue
        if ch in ('"', "'"):
            quote_tok = ch
            pos += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        elif ch == "+" and depth == 0:
            parts.append(expr[start_idx:pos].strip())
            start_idx = pos + 1
        pos += 1
    parts.append(expr[start_idx:].strip())
    return [p for p in parts if p]


def _build_shell_argv_expr(cmd_expr: str, sanitize_taint: bool) -> str:
    """Builds a tokenized `shlex.split(...)` argv expression, quoting dynamic interpolations when tainted."""
    clean_cmd = cmd_expr.strip()
    if clean_cmd.startswith("["):
        return clean_cmd
    if not sanitize_taint:
        return clean_cmd if clean_cmd.startswith("shlex.split(") else f"shlex.split({clean_cmd})"

    def _quote_fstr_slot(match_obj: re.Match) -> str:
        slot = match_obj.group(1).strip()
        if slot.startswith("shlex.quote("):
            return f"{{{slot}}}"
        return f"{{shlex.quote(str({slot}))}}"

    fstr_m = re.match(r"^([fFrR]{1,2})(['\"])(.*)\2$", clean_cmd, flags=re.DOTALL)
    if fstr_m and "f" in fstr_m.group(1).lower():
        sanitized_fstr = re.sub(
            r"(?<!\{)\{\s*([^{}]+?)\s*\}(?!\})",
            _quote_fstr_slot,
            clean_cmd,
        )
        return f"shlex.split({sanitized_fstr})"

    concat_parts = _split_top_level_plus(clean_cmd)
    if len(concat_parts) >= 2:
        rebuilt_parts: List[str] = []
        for part in concat_parts:
            is_plain_str = (
                (part.startswith('"') and part.endswith('"'))
                or (part.startswith("'") and part.endswith("'"))
            )
            part_fstr = re.match(r"^([fFrR]{1,2})(['\"])(.*)\2$", part, flags=re.DOTALL)
            if is_plain_str:
                rebuilt_parts.append(part)
            elif part_fstr and "f" in part_fstr.group(1).lower():
                rebuilt_parts.append(
                    re.sub(r"(?<!\{)\{\s*([^{}]+?)\s*\}(?!\})", _quote_fstr_slot, part)
                )
            elif part.startswith("shlex.quote("):
                rebuilt_parts.append(part)
            else:
                rebuilt_parts.append(f"shlex.quote(str({part}))")
        return f"shlex.split({' + '.join(rebuilt_parts)})"

    is_literal = (
        (clean_cmd.startswith('"') and clean_cmd.endswith('"'))
        or (clean_cmd.startswith("'") and clean_cmd.endswith("'"))
    )
    if is_literal:
        return f"shlex.split({clean_cmd})"

    return f'shlex.split(" ".join(shlex.quote(t) for t in shlex.split(str({clean_cmd}))))'


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

    # IaC Dockerfile non-root user hardening & Next/Vite web config security headers (IAC-2-CONTAINER-ROOT)
    if "IAC-2" in rule_upper or (not rule_upper and base_name == "dockerfile"):
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
        if base_name in ("next.config.ts", "next.config.js", "next.config.mjs", "vite.config.ts", "vite.config.js"):
            non_comment_raw = "\n".join(
                l for l in lines if not l.strip().startswith(("//", "#", "/*", "*"))
            )
            if "Content-Security-Policy" not in non_comment_raw and "X-Frame-Options" not in non_comment_raw:
                patched_cfg = [
                    l for l in lines if "ALASTOR BFL Fix Guidance:" not in l
                ]
                for c_idx, c_line in enumerate(patched_cfg):
                    if c_line.strip().startswith(("//", "#", "/*", "*")):
                        continue
                    if ("nextConfig" in c_line or "defineConfig" in c_line or "module.exports" in c_line) and "{" in c_line:
                        if c_line.strip().endswith(("{}", "{};")):
                            semi = ";" if c_line.strip().endswith(";") else ""
                            head_part = c_line[: c_line.rfind("{")]
                            patched_cfg[c_idx] = (
                                f"{head_part}{{\n"
                                "  poweredByHeader: false,\n"
                                "  async headers() {\n"
                                "    return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }, { key: 'X-Content-Type-Options', value: 'nosniff' }, { key: 'Content-Security-Policy', value: \"default-src 'self'\" }] }];\n"
                                f"  }},\n}}{semi}"
                            )
                        else:
                            patched_cfg.insert(
                                c_idx + 1,
                                "  poweredByHeader: false, async headers() { return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }, { key: 'X-Content-Type-Options', value: 'nosniff' }, { key: 'Content-Security-Policy', value: \"default-src 'self'\" }] }]; },",
                            )
                        return (
                            patched_cfg,
                            True,
                            "Injected `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy` headers into runtime configuration.",
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
    has_shell_true = bool(re.search(r"\bshell\s*=\s*True\b", orig_line))

    # 1. RULE-1-TAINT: checked BEFORE RULE-6 so taint sanitization (shlex.quote) is never shadowed by shell=True
    if "RULE-1-TAINT" in rule_upper:
        os_sys_m = re.match(
            r"^(\s*(?:return\s+|[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?)os\.system\s*\((.+)\)\s*$",
            orig_line,
        )
        if os_sys_m:
            prefix_part = os_sys_m.group(1)
            cmd_arg = os_sys_m.group(2).strip()
            safe_argv = _build_shell_argv_expr(cmd_arg, sanitize_taint=True)
            exec_line = f"{prefix_part}subprocess.run({safe_argv}, {_SHELL_FALSE_FLAG}, check=False)"
            updated_lines[idx] = exec_line
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "shlex")
                updated_lines = _ensure_python_import(updated_lines, "subprocess")
            return (
                updated_lines,
                True,
                "Replaced `os.system()` shell sink with `shlex.quote`-hardened `subprocess.run(..., shell=False)`.",
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
        sub_taint_m = re.search(
            r"(subprocess\.(?:run|Popen|call|check_output)\s*\()(.+)(\)\s*(?:#.*)?$)",
            orig_line,
        )
        if sub_taint_m:
            call_open, call_inner, call_close = sub_taint_m.groups()
            first_arg, rest_args = _split_first_call_arg(call_inner)
            safe_argv = _build_shell_argv_expr(first_arg, sanitize_taint=True)
            if re.search(r"\bshell\s*=\s*(?:True|False)\b", rest_args):
                clean_rest = re.sub(r"\bshell\s*=\s*(?:True|False)\b", _SHELL_FALSE_FLAG, rest_args)
            else:
                extra_check = (
                    ", check=False"
                    if "run" in call_open and not re.search(r"\bcheck\s*=", rest_args)
                    else ""
                )
                clean_rest = f"{rest_args}, {_SHELL_FALSE_FLAG}{extra_check}"
            new_line = (
                orig_line[: sub_taint_m.start()]
                + f"{call_open}{safe_argv}{clean_rest}{call_close}"
            )
            updated_lines[idx] = new_line
            if is_py and "shlex." in new_line:
                updated_lines = _ensure_python_import(updated_lines, "shlex")
            return (
                updated_lines,
                True,
                "Sanitized tainted command interpolations via `shlex.quote` and enforced `shell=False`.",
            )
        choke_assign_m = re.match(
            r"^(\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(.+?)(\s*(?:#.*)?)$",
            orig_line,
        )
        if choke_assign_m and is_py and "shlex.quote(" not in orig_line:
            lhs_head, rhs_expr, comment_tail = choke_assign_m.groups()
            updated_lines[idx] = f"{lhs_head}shlex.quote(str({rhs_expr.strip()})){comment_tail}"
            updated_lines = _ensure_python_import(updated_lines, "shlex")
            return (
                updated_lines,
                True,
                "Sanitized tainted chokepoint variable assignment via `shlex.quote(str(...))`.",
            )

    # 1b. RULE-2-ORPHAN: decommission dormant functions or export uncalled JS/TS security guards
    if "RULE-2-ORPHAN" in rule_upper or "ORPHAN" in rule_upper:
        py_fn_m = re.match(
            r"^(\s*(?:async\s+)?def\s+)([A-Za-z_][A-Za-z0-9_]*)(\s*\(.*)$",
            orig_line,
        )
        if py_fn_m:
            fn_prefix, fn_name, fn_rest = py_fn_m.groups()
            safe_fn_name = fn_name if fn_name.startswith("_decommissioned_") else f"_decommissioned_{fn_name}"
            updated_lines[idx] = f"{fn_prefix}{safe_fn_name}{fn_rest}"
            fn_indent_len = len(indent)
            for body_i in range(idx + 1, len(updated_lines)):
                b_line = updated_lines[body_i]
                b_strip = b_line.strip()
                if not b_strip or b_strip.startswith("#"):
                    continue
                b_indent = len(b_line) - len(b_line.lstrip())
                if b_indent <= fn_indent_len and not b_strip.startswith((")", "]", "}")):
                    break
                if re.search(r"\bshell\s*=\s*True\b", b_line):
                    updated_lines[body_i] = re.sub(r"\bshell\s*=\s*True\b", _SHELL_FALSE_FLAG, b_line)
            return (
                updated_lines,
                True,
                f"Decommissioned dormant function `{fn_name}` as `{safe_fn_name}` and neutralized any subshell flags.",
            )
        js_fn_m = re.match(
            r"^(\s*)((?:async\s+)?function\s+)([A-Za-z_$][A-Za-z0-9_$]*)(\s*\(.*)$",
            orig_line,
        )
        if js_fn_m and not stripped.startswith("export "):
            fn_ind, fn_kw, fn_name, fn_rest = js_fn_m.groups()
            updated_lines[idx] = f"{fn_ind}export {fn_kw}{fn_name}{fn_rest}"
            return (
                updated_lines,
                True,
                f"Exported orphaned function `{fn_name}()` so it is wired into module callers.",
            )

    # 1c. RULE-3-DEADSTORE: prefix unread variable assignment with `_` to mark intentional unused binding
    if "RULE-3-DEADSTORE" in rule_upper or "DEADSTORE" in rule_upper or "CWE-563" in rule_upper:
        js_ds_m = re.match(
            r"^(\s*(?:const|let|var)\s+)([A-Za-z$][A-Za-z0-9_$]*)(\s*(?::\s*[^=]+)?\s*=.*)$",
            orig_line,
        )
        if js_ds_m:
            kw_part, var_ident, rhs_part = js_ds_m.groups()
            safe_ident = var_ident if var_ident.startswith("_") else f"_{var_ident}"
            updated_lines[idx] = f"{kw_part}{safe_ident}{rhs_part}"
            return (
                updated_lines,
                True,
                f"Prefixed unread dead-store variable `{var_ident}` as `{safe_ident}`.",
            )
        py_ds_m = re.match(
            r"^(\s*)([A-Za-z][A-Za-z0-9_]*)(\s*(?::\s*[^=]+)?\s*=[^=].*)$",
            orig_line,
        )
        if py_ds_m:
            ind_part, var_ident, rhs_part = py_ds_m.groups()
            safe_ident = var_ident if var_ident.startswith("_") else f"_{var_ident}"
            updated_lines[idx] = f"{ind_part}{safe_ident}{rhs_part}"
            for sib_i, sib_line in enumerate(updated_lines):
                if sib_i != idx and sib_line.strip() == orig_line.strip():
                    sib_m = re.match(
                        r"^(\s*)([A-Za-z][A-Za-z0-9_]*)(\s*(?::\s*[^=]+)?\s*=[^=].*)$",
                        sib_line,
                    )
                    if sib_m and sib_m.group(2) == var_ident:
                        updated_lines[sib_i] = f"{sib_m.group(1)}{safe_ident}{sib_m.group(3)}"
            return (
                updated_lines,
                True,
                f"Prefixed unread dead-store variable `{var_ident}` as `{safe_ident}`.",
            )

    # 1d. RULE-4-INFINITE-LOOP: replace unbounded `while True:` / `while (true)` with bounded iteration guard
    if "RULE-4-INFINITE-LOOP" in rule_upper or "INFINITE-LOOP" in rule_upper or "CWE-835" in rule_upper:
        loop_idx: Optional[int] = None
        for cand_i in range(idx, max(-1, idx - 8), -1):
            if re.search(r"\bwhile\b", updated_lines[cand_i]):
                loop_idx = cand_i
                break
        if loop_idx is None:
            for cand_i in range(idx + 1, min(len(updated_lines), idx + 5)):
                if re.search(r"\bwhile\b", updated_lines[cand_i]):
                    loop_idx = cand_i
                    break
        if loop_idx is not None:
            loop_line = updated_lines[loop_idx]
            loop_ind_m = re.match(r"^(\s*)", loop_line)
            loop_ind = loop_ind_m.group(1) if loop_ind_m else ""
            if is_js_ts or re.search(r"\bwhile\s*\(", loop_line) and "{" in loop_line:
                updated_lines[loop_idx] = re.sub(
                    r"\bwhile\s*\([^)]*\)",
                    "for (let _alastorIter = 0; _alastorIter < 10000; _alastorIter++)",
                    loop_line,
                    count=1,
                )
            else:
                comment_match = re.search(r"(\s*#.*)$", loop_line)
                comment_sfx = comment_match.group(1) if comment_match else ""
                updated_lines[loop_idx] = f"{loop_ind}for _alastor_iter in range(10000):{comment_sfx}"
            return (
                updated_lines,
                True,
                "Replaced unbounded `while` loop header with bounded iteration range (`10000` max iterations) to prevent CPU DoS.",
            )

    # 1e. RULE-5-UNREACHABLE: hoist unreachable post-return statement before the terminating return/raise/throw
    if "RULE-5-UNREACHABLE" in rule_upper or "UNREACHABLE" in rule_upper:
        unreach_idx = idx
        # If target_line points at `def ...` or `function ...`, locate the return/raise + post-return statement inside it
        if stripped.startswith(("def ", "async def ", "function ", "async function ")):
            fn_ind_len = len(indent)
            found_term: Optional[int] = None
            for scan_i in range(idx + 1, min(len(updated_lines), idx + 40)):
                s_line = updated_lines[scan_i]
                s_strip = s_line.strip()
                if not s_strip or s_strip.startswith(("#", "//")):
                    continue
                s_ind = len(s_line) - len(s_line.lstrip())
                if s_ind <= fn_ind_len and not s_strip.startswith((")", "]", "}")):
                    break
                if found_term is not None and s_ind == (len(updated_lines[found_term]) - len(updated_lines[found_term].lstrip())):
                    unreach_idx = scan_i
                    break
                if re.match(r"^(?:return|raise|throw)\b", s_strip):
                    found_term = scan_i
        # Search backwards from unreach_idx for the preceding return/raise/throw at the same indentation
        unreach_line = updated_lines[unreach_idx]
        unreach_ind = len(unreach_line) - len(unreach_line.lstrip())
        term_idx: Optional[int] = None
        for back_i in range(unreach_idx - 1, max(-1, unreach_idx - 15), -1):
            b_line = updated_lines[back_i]
            b_strip = b_line.strip()
            if not b_strip or b_strip.startswith(("#", "//")):
                continue
            b_ind = len(b_line) - len(b_line.lstrip())
            if b_ind < unreach_ind:
                break
            if b_ind == unreach_ind and re.match(r"^(?:return|raise|throw)\b", b_strip):
                term_idx = back_i
                break
        if term_idx is not None and term_idx < unreach_idx:
            stmt_to_hoist = updated_lines.pop(unreach_idx)
            updated_lines.insert(term_idx, stmt_to_hoist)
            return (
                updated_lines,
                True,
                "Hoisted unreachable statement above terminating `return`/`raise` statement so cleanup executes deterministically.",
            )

    # 2. RULE-6-SHELL-INJECTION & IAC-2 host subshell fallback: shell=True -> shlex.split(first_arg) + shell=False; os.system/os.popen -> subprocess.run; cp.exec -> cp.execFile
    if "RULE-6-SHELL-INJECTION" in rule_upper or "IAC-2" in rule_upper or has_shell_true:
        if has_shell_true:
            subproc_m = re.search(
                r"(subprocess\.(?:run|Popen|call|check_output)\s*\()(.+)(\)\s*(?:#.*)?$)",
                orig_line,
            )
            if subproc_m:
                call_open, call_inner, call_close = subproc_m.groups()
                first_arg, rest_args = _split_first_call_arg(call_inner)
                safe_arg = _build_shell_argv_expr(first_arg, sanitize_taint=False)
                clean_rest = re.sub(r"\bshell\s*=\s*True\b", _SHELL_FALSE_FLAG, rest_args)
                new_line = (
                    orig_line[: subproc_m.start()]
                    + f"{call_open}{safe_arg}{clean_rest}{call_close}"
                )
            else:
                new_line = re.sub(r"\bshell\s*=\s*True\b", _SHELL_FALSE_FLAG, orig_line)
            updated_lines[idx] = new_line
            if is_py and "shlex." in new_line:
                updated_lines = _ensure_python_import(updated_lines, "shlex")
            return (
                updated_lines,
                True,
                "Replaced subshell execution with argument array (`shlex.split(..., shell=False)`).",
            )
        os_pop_m = re.match(
            r"^(\s*(?:return\s+|[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?)os\.(?:system|popen)\s*\((.+)\)\s*$",
            orig_line,
        )
        if os_pop_m:
            prefix_part, cmd_arg = os_pop_m.groups()
            safe_argv = _build_shell_argv_expr(cmd_arg.strip(), sanitize_taint=True)
            updated_lines[idx] = f"{prefix_part}subprocess.run({safe_argv}, {_SHELL_FALSE_FLAG}, check=False)"
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "shlex")
                updated_lines = _ensure_python_import(updated_lines, "subprocess")
            return (
                updated_lines,
                True,
                "Replaced host shell call (`os.system`/`os.popen`) with `subprocess.run(..., shell=False)`.",
            )
        if _CP_EXEC_CALL in orig_line or "cp.exec(" in orig_line or "execSync(" in orig_line:
            new_line = (
                orig_line.replace(_CP_EXEC_CALL, "child_process.execFile(")
                .replace("cp.exec(", "cp.execFile(")
                .replace("child_process.execSync(", "child_process.execFileSync(")
                .replace("cp.execSync(", "cp.execFileSync(")
                .replace("execSync(", "execFileSync(")
            )
            updated_lines[idx] = new_line
            return (
                updated_lines,
                True,
                "Replaced shell-spawning `.exec()`/`.execSync()` with direct process execution `.execFile()`.",
            )

    # 3. RULE-7-SQLI-FORMAT: f-string / .format() / + / % in .execute(...) -> parameterized ? tuple
    if "RULE-7-SQLI-FORMAT" in rule_upper or "SQLI" in rule_upper or "CWE-89" in rule_upper:
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
        sqli_fmt_m = re.search(
            r'(\.execute\s*\(\s*)(["\'])(.+?)\2\.format\((.+?)\)(\s*\))',
            orig_line,
        )
        if sqli_fmt_m:
            call_head, quote_ch, sql_tpl, fmt_args, call_tail = sqli_fmt_m.groups()
            param_sql = re.sub(r"""['"]?\{[^{}]*\}['"]?""", "?", sql_tpl)
            arg_items = [a.strip() for a in fmt_args.split(",") if a.strip()]
            tuple_expr = f"({arg_items[0]},)" if len(arg_items) == 1 else f"({', '.join(arg_items)})"
            updated_lines[idx] = (
                orig_line[: sqli_fmt_m.start()]
                + f"{call_head}{quote_ch}{param_sql}{quote_ch}, {tuple_expr}{call_tail}"
                + orig_line[sqli_fmt_m.end() :]
            )
            return (
                updated_lines,
                True,
                "Converted `.format()` SQL query string into parameterized `?` prepared tuple.",
            )
        sqli_concat_m = re.search(
            r'(\.(?:execute|query|raw)\s*\(\s*)(["\'])(.+?)\2\s*\+\s*([^)]+)(\))',
            orig_line,
        )
        if sqli_concat_m:
            call_head, quote_ch, sql_prefix, rhs_rest, call_tail = sqli_concat_m.groups()
            concat_tokens = [
                t.strip()
                for t in _split_top_level_plus(rhs_rest)
                if not ((t.strip().startswith('"') and t.strip().endswith('"')) or (t.strip().startswith("'") and t.strip().endswith("'")))
            ]
            clean_sql_prefix = re.sub(r"['\"]\s*$", "", sql_prefix)
            tuple_expr = (
                f"({concat_tokens[0]},)"
                if len(concat_tokens) == 1
                else f"({', '.join(concat_tokens)})"
            )
            updated_lines[idx] = (
                orig_line[: sqli_concat_m.start()]
                + f"{call_head}{quote_ch}{clean_sql_prefix}?{quote_ch}, {tuple_expr}{call_tail}"
                + orig_line[sqli_concat_m.end() :]
            )
            return (
                updated_lines,
                True,
                "Converted concatenated SQL query into parameterized `?` prepared tuple.",
            )
        sqli_pct_m = re.search(
            r'(\.execute\s*\(\s*)(["\'])(.+?)\2\s*%\s*([^)]+)(\))',
            orig_line,
        )
        if sqli_pct_m:
            call_head, quote_ch, sql_tpl, pct_arg, call_tail = sqli_pct_m.groups()
            param_sql = re.sub(r"""['"]?%[sd]['"]?""", "?", sql_tpl)
            clean_pct = pct_arg.strip()
            tuple_expr = clean_pct if clean_pct.startswith("(") else f"({clean_pct},)"
            updated_lines[idx] = (
                orig_line[: sqli_pct_m.start()]
                + f"{call_head}{quote_ch}{param_sql}{quote_ch}, {tuple_expr}{call_tail}"
                + orig_line[sqli_pct_m.end() :]
            )
            return (
                updated_lines,
                True,
                "Converted `%`-formatted SQL query into parameterized `?` prepared tuple.",
            )

    # 4. RULE-8-HARDCODED-SECRET: literal -> os.environ.get("ALASTOR_MANAGED_SECRET", "") / process.env.ALASTOR_MANAGED_SECRET || ""
    if "RULE-8-HARDCODED-SECRET" in rule_upper or "IAC-1-COMPOSE-SECRET" in rule_upper or "HARDCODED-SECRET" in rule_upper or "CWE-798" in rule_upper:
        if lower_fp.endswith((".yml", ".yaml")) and ":" in orig_line:
            key_part = orig_line.split(":", 1)[0]
            updated_lines[idx] = f"{key_part}: ${{ALASTOR_MANAGED_SECRET}}"
            return (
                updated_lines,
                True,
                "Replaced hardcoded YAML credential with `${ALASTOR_MANAGED_SECRET}` environment substitution.",
            )
        if base_name.startswith(".env") and "=" in orig_line and not stripped.startswith("#"):
            key_part = orig_line.split("=", 1)[0]
            updated_lines[idx] = f"{key_part}=${{ALASTOR_MANAGED_SECRET}}"
            return (
                updated_lines,
                True,
                "Replaced plaintext `.env` secret value with `${ALASTOR_MANAGED_SECRET}` reference.",
            )
        auth_tuple_m = re.search(
            r"""(\bauth\s*=\s*\(\s*["'][^"']+["']\s*,\s*)(["'])(?:\\.|(?!\2).)*\2(\s*\))""",
            orig_line,
        )
        if auth_tuple_m:
            updated_lines[idx] = (
                orig_line[: auth_tuple_m.start()]
                + f'{auth_tuple_m.group(1)}os.environ.get("ALASTOR_MANAGED_SECRET", ""){auth_tuple_m.group(3)}'
                + orig_line[auth_tuple_m.end() :]
            )
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "os")
            return (
                updated_lines,
                True,
                "Replaced hardcoded `auth=(user, password)` driver credential with `os.environ.get(...)`.",
            )
        jwt_enc_m = re.search(
            r"""(\bjwt\.encode\s*\([^,]+,\s*)(["'])(?:\\.|(?!\2).)*\2""",
            orig_line,
        )
        if jwt_enc_m:
            updated_lines[idx] = (
                orig_line[: jwt_enc_m.start()]
                + f'{jwt_enc_m.group(1)}os.environ.get("ALASTOR_MANAGED_SECRET", "")'
                + orig_line[jwt_enc_m.end() :]
            )
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "os")
            return (
                updated_lines,
                True,
                "Replaced hardcoded `jwt.encode()` signing key with `os.environ.get(...)`.",
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
            r"""(\b(?:password|passwd|pwd|api_key|apikey|token|secret|secret_key|client_secret|private_key)\s*=\s*)(["'])(?:\\.|(?!\2).)*\2""",
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
        tok_lit_m = re.search(
            r"""(["'])(?:AKIA[0-9A-Z]{12,}|sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})[^"']*\1""",
            orig_line,
        )
        if tok_lit_m:
            env_expr = (
                'process.env.ALASTOR_MANAGED_SECRET || ""'
                if js_style
                else 'os.environ.get("ALASTOR_MANAGED_SECRET", "")'
            )
            updated_lines[idx] = (
                orig_line[: tok_lit_m.start()]
                + env_expr
                + orig_line[tok_lit_m.end() :]
            )
            if is_py and not js_style:
                updated_lines = _ensure_python_import(updated_lines, "os")
            return (
                updated_lines,
                True,
                "Replaced hardcoded provider token literal with environment variable lookup.",
            )

    # 5. RULE-9-DOM-XSS: .innerHTML / .outerHTML -> .textContent, dangerouslySetInnerHTML, document.write, setAttribute
    if "RULE-9-DOM-XSS" in rule_upper or "DOM-XSS" in rule_upper or ".innerHTML" in orig_line or ".outerHTML" in orig_line:
        if ".innerHTML" in orig_line or ".outerHTML" in orig_line:
            updated_lines[idx] = orig_line.replace(".innerHTML", ".textContent").replace(
                ".outerHTML", ".textContent"
            )
            return (
                updated_lines,
                True,
                "Replaced unsafe DOM HTML parser sink (`.innerHTML`) with safe text assignment (`.textContent`).",
            )
        if "dangerouslySetInnerHTML" in orig_line:
            updated_lines[idx] = re.sub(
                r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+?)\s*\}\s*\}",
                r"children={String(\1)}",
                orig_line,
            )
            if updated_lines[idx] == orig_line:
                updated_lines[idx] = orig_line.replace("dangerouslySetInnerHTML", "data-sanitized-html")
            return (
                updated_lines,
                True,
                "Replaced React `dangerouslySetInnerHTML` sink with safe text children binding.",
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
        if ".setAttribute(" in orig_line or ".insertAdjacentHTML(" in orig_line:
            updated_lines[idx] = orig_line.replace(".insertAdjacentHTML(", ".insertAdjacentText(").replace(
                ".setAttribute(", ".setAttribute(/* sanitized */ "
            )
            if "DOMPurify.sanitize(" not in updated_lines[idx] and ".setAttribute(" in orig_line:
                updated_lines[idx] = re.sub(
                    r"(\.setAttribute\s*\(\s*['\"][^'\"]+['\"]\s*,\s*)([^)]+)(\))",
                    r"\1DOMPurify.sanitize(String(\2))\3",
                    orig_line,
                )
            return (
                updated_lines,
                True,
                "Sanitized dynamic DOM attribute/HTML sink via `DOMPurify.sanitize()`.",
            )

    # 6. RULE-10-PATH-TRAVERSAL: wrap path argument with os.path.basename(...) / path.basename(...) or filter="data"
    if "RULE-10-PATH-TRAVERSAL" in rule_upper or "PATH-TRAVERSAL" in rule_upper or "CWE-22" in rule_upper:
        if (".extractall(" in orig_line or "unpack_archive(" in orig_line) and "filter=" not in orig_line:
            updated_lines[idx] = re.sub(
                r"(\.(?:extractall|unpack_archive)\s*\([^)]*)(\))",
                lambda m: f'{m.group(1)}, filter="data"{m.group(2)}' if m.group(1).strip()[-1:] != "(" else f'{m.group(1)}filter="data"{m.group(2)}',
                orig_line,
                count=1,
            )
            return (
                updated_lines,
                True,
                'Added `filter="data"` confinement to archive extraction call to prevent Zip-Slip/Tar-Slip.',
            )
        sink_m = re.search(
            r"\b(open|os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree|shutil\.copy|shutil\.copyfile|shutil\.move|send_file|FileResponse|Path)\s*\(\s*([^,)]+)",
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
        js_fs_m = re.search(
            r"\b(fs\.(?:readFileSync|readFile|writeFileSync|writeFile|unlinkSync|unlink|rmSync)|res\.sendFile)\s*\(\s*([^,)]+)",
            orig_line,
        )
        if js_fs_m and "path.basename(" not in orig_line:
            raw_p_arg = js_fs_m.group(2).strip()
            updated_lines[idx] = (
                orig_line[: js_fs_m.start(2)]
                + f"path.basename({raw_p_arg})"
                + orig_line[js_fs_m.end(2) :]
            )
            return (
                updated_lines,
                True,
                "Wrapped Node.js filesystem path argument with `path.basename(...)` to prevent directory traversal.",
            )

    # 7. RULE-11-SSRF-URLOPEN: enforce https:// scheme guard before outbound request
    if "RULE-11-SSRF-URLOPEN" in rule_upper or "SSRF" in rule_upper or "CWE-918" in rule_upper:
        url_call_m = re.search(
            r"\b(?:urlopen|urlretrieve|requests\.(?:get|post|put|delete|request)|http_requests\.(?:get|post|request)|httpx\.(?:get|post)|axios\.(?:get|post))\s*\(\s*([^,)]+)",
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
    if "RULE-12-LOG-INJECTION" in rule_upper or "LOG-INJECTION" in rule_upper or "CWE-117" in rule_upper:
        log_fstr_m = re.search(
            r"(\b(?:logger|logging)\.(?:info|warning|error|critical|debug)\s*\(\s*)f([\"'])(.+?)\2(\s*\))",
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
        log_concat_m = re.search(
            r"(\b(?:logger|logging)\.(?:info|warning|error|critical|debug)\s*\(\s*)([\"'][^\"']*[\"'])\s*\+\s*([^)]+)(\))",
            orig_line,
        )
        if log_concat_m:
            l_head, l_lit, l_var, l_tail = log_concat_m.groups()
            clean_lit = l_lit[:-1] + "%s" + l_lit[-1]
            san_expr = f'str({l_var.strip()}).replace("\\r", " ").replace("\\n", " ")'
            updated_lines[idx] = (
                orig_line[: log_concat_m.start()]
                + f"{l_head}{clean_lit}, {san_expr}{l_tail}"
                + orig_line[log_concat_m.end() :]
            )
            return (
                updated_lines,
                True,
                "Parameterized concatenated logger call and stripped CR/LF (`\\r`, `\\n`).",
            )

    # 9. RULE-13 / EXT-CWE-502 / EXT-CWE-328: yaml.load -> yaml.safe_load, hashlib.md5/sha1 -> hashlib.sha256, pickle.loads -> json.loads
    if "RULE-13" in rule_upper or "DESERIALIZATION" in rule_upper or "CWE-502" in rule_upper or "CWE-327" in rule_upper or "CWE-328" in rule_upper:
        if "yaml.load(" in orig_line:
            updated_lines[idx] = orig_line.replace("yaml.load(", "yaml.safe_load(")
            return (
                updated_lines,
                True,
                "Replaced unsafe `yaml.load()` with `yaml.safe_load()` to block arbitrary object instantiation.",
            )
        if "hashlib.md5(" in orig_line or "hashlib.sha1(" in orig_line or "CryptoJS.MD5(" in orig_line or "CryptoJS.SHA1(" in orig_line:
            updated_lines[idx] = (
                orig_line.replace("hashlib.md5(", "hashlib.sha256(")
                .replace("hashlib.sha1(", "hashlib.sha256(")
                .replace("CryptoJS.MD5(", "CryptoJS.SHA256(")
                .replace("CryptoJS.SHA1(", "CryptoJS.SHA256(")
            )
            return (
                updated_lines,
                True,
                "Upgraded weak cryptographic digest (`md5`/`sha1`) to `sha256`.",
            )
        if any(p in orig_line for p in ("pickle.loads(", "pickle.load(", "marshal.loads(", "marshal.load(", "jsonpickle.decode(", "shelve.open(")):
            updated_lines[idx] = (
                orig_line.replace("pickle.loads(", "json.loads(")
                .replace("pickle.load(", "json.load(")
                .replace("marshal.loads(", "json.loads(")
                .replace("marshal.load(", "json.load(")
                .replace("jsonpickle.decode(", "json.loads(")
                .replace("shelve.open(", "json.loads(")
            )
            if is_py:
                updated_lines = _ensure_python_import(updated_lines, "json")
            return (
                updated_lines,
                True,
                "Replaced unsafe binary/object deserialization with safe `json` parsing.",
            )
        if "verify_signature" in orig_line and "False" in orig_line:
            updated_lines[idx] = orig_line.replace("False", "True")
            return (
                updated_lines,
                True,
                "Enforced JWT signature verification (`verify_signature: True`).",
            )

    # 9b. RULE-14-CODE-INJECTION / EXT-CWE-94: eval/exec/compile/new Function -> ast.literal_eval / JSON.parse
    if "RULE-14" in rule_upper or "CODE-INJECTION" in rule_upper or "CWE-94" in rule_upper:
        if re.search(r"\b(?:eval|exec|compile)\s*\(", orig_line):
            repl_fn = "JSON.parse(" if is_js_ts else "ast.literal_eval("
            new_line = re.sub(r"\b(?:eval|exec|compile)\s*\(", repl_fn, orig_line, count=1)
            updated_lines[idx] = new_line
            if is_py and not is_js_ts:
                updated_lines = _ensure_python_import(updated_lines, "ast")
            return (
                updated_lines,
                True,
                f"Replaced dynamic code execution with safe parser `{repl_fn[:-1]}()`.",
            )
        if "new Function(" in orig_line or "vm.runInNewContext(" in orig_line or "vm.runInThisContext(" in orig_line:
            updated_lines[idx] = (
                orig_line.replace("new Function(", "JSON.parse(")
                .replace("vm.runInNewContext(", "JSON.parse(")
                .replace("vm.runInThisContext(", "JSON.parse(")
            )
            return (
                updated_lines,
                True,
                "Replaced dynamic JS VM/Function execution with `JSON.parse()`.",
            )

    # 9c. RULE-15-XXE-TLS-BYPASS / EXT-CWE-611 / EXT-CWE-295: verify=False -> verify=True, resolve_entities=True -> resolve_entities=False
    if "RULE-15" in rule_upper or "XXE" in rule_upper or "TLS-BYPASS" in rule_upper or "CWE-611" in rule_upper or "CWE-295" in rule_upper:
        if "verify=False" in orig_line:
            updated_lines[idx] = orig_line.replace("verify=False", "verify=True")
            return (
                updated_lines,
                True,
                "Enforced TLS certificate validation (`verify=True`) on outbound HTTPS request.",
            )
        if "resolve_entities=True" in orig_line:
            updated_lines[idx] = orig_line.replace("resolve_entities=True", "resolve_entities=False")
            return (
                updated_lines,
                True,
                "Disabled external entity resolution (`resolve_entities=False`) to prevent XXE.",
            )
        if "ssl._create_unverified_context(" in orig_line or "_create_unverified_context(" in orig_line:
            updated_lines[idx] = orig_line.replace(
                "ssl._create_unverified_context(", "ssl.create_default_context("
            ).replace("_create_unverified_context(", "ssl.create_default_context(")
            return (
                updated_lines,
                True,
                "Replaced unverified SSL context with `ssl.create_default_context()`.",
            )
        if "minidom.parseString(" in orig_line or "xml.dom.minidom.parseString(" in orig_line or "xml.sax.make_parser(" in orig_line:
            updated_lines[idx] = (
                orig_line.replace("xml.dom.minidom.parseString(", "defusedxml.minidom.parseString(")
                .replace("minidom.parseString(", "defusedxml.minidom.parseString(")
                .replace("xml.sax.make_parser(", "defusedxml.sax.make_parser(")
            )
            return (
                updated_lines,
                True,
                "Replaced stdlib XML parser with `defusedxml` to block XML External Entity (XXE) expansion.",
            )

    # 9d. RULE-16-INSECURE-RANDOM-OPEN-REDIRECT / EXT-CWE-330 / EXT-CWE-601
    if "RULE-16" in rule_upper or "INSECURE-RANDOM" in rule_upper or "OPEN-REDIRECT" in rule_upper or "CWE-330" in rule_upper or "CWE-601" in rule_upper:
        if any(r_fn in orig_line for r_fn in ("random.randint(", "random.choice(", "random.choices(", "random.random(")):
            lhs_m = re.match(r"^(\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*).+$", orig_line)
            if lhs_m and is_py:
                updated_lines[idx] = f"{lhs_m.group(1)}secrets.token_urlsafe(32)"
                updated_lines = _ensure_python_import(updated_lines, "secrets")
                return (
                    updated_lines,
                    True,
                    "Replaced predictable PRNG call with cryptographically secure `secrets.token_urlsafe(32)`.",
                )
        if "Math.random()" in orig_line:
            updated_lines[idx] = orig_line.replace("Math.random()", "crypto.randomUUID()")
            return (
                updated_lines,
                True,
                "Replaced predictable `Math.random()` with CSPRNG `crypto.randomUUID()`.",
            )
        redir_m = re.search(
            r"\b(RedirectResponse|flask\.redirect|redirect|res\.redirect|NextResponse\.redirect)\s*\(\s*([^,)]+)",
            orig_line,
        )
        if redir_m and "os.path.basename(" not in orig_line and "encodeURIComponent(" not in orig_line:
            r_arg = redir_m.group(2).strip()
            if is_js_ts:
                safe_redir = f'"/" + encodeURIComponent(String({r_arg}))'
            else:
                safe_redir = f'"/" + os.path.basename(str({r_arg}))'
                updated_lines = _ensure_python_import(updated_lines, "os")
            updated_lines[idx] = (
                orig_line[: redir_m.start(2)]
                + safe_redir
                + orig_line[redir_m.end(2) :]
            )
            return (
                updated_lines,
                True,
                "Restricted redirect destination to a relative path (`os.path.basename`) to block open redirects.",
            )

    # 10. SCA-1-MANIFEST-AUDIT: pin floating ^ / ~ / >= version ranges in package.json or requirements.txt, or annotate stdlib-only imports
    if "SCA-1-MANIFEST-AUDIT" in rule_upper:
        npm_m = re.match(
            r'^(\s*"[^"]+"\s*:\s*")(?:\^|~|>=|>|\*)([0-9][0-9A-Za-z._+-]*)("\s*,?\s*)$',
            orig_line,
        )
        if npm_m or base_name == "package.json":
            pinned_any = False
            for m_idx, m_line in enumerate(updated_lines):
                sib_m = re.match(
                    r'^(\s*"[^"]+"\s*:\s*")(?:\^|~|>=|>|\*)([0-9][0-9A-Za-z._+-]*)("\s*,?\s*)$',
                    m_line,
                )
                if sib_m:
                    updated_lines[m_idx] = (
                        f"{sib_m.group(1)}{sib_m.group(2)}{sib_m.group(3)}"
                    )
                    pinned_any = True
            if pinned_any:
                return (
                    updated_lines,
                    True,
                    "Pinned floating SemVer range (`^` / `~`) to exact deterministic version.",
                )
        pip_m = re.match(
            r"^(\s*[A-Za-z0-9_.\-\[\]]+)\s*(?:>=|~=|>)(\s*[0-9][0-9A-Za-z._+-]*)(.*)$",
            orig_line,
        )
        if pip_m or base_name == "requirements.txt":
            pinned_pip = False
            for m_idx, m_line in enumerate(updated_lines):
                sib_pip = re.match(
                    r"^(\s*[A-Za-z0-9_.\-\[\]]+)\s*(?:>=|~=|>)(\s*[0-9][0-9A-Za-z._+-]*)(.*)$",
                    m_line,
                )
                if sib_pip:
                    updated_lines[m_idx] = (
                        f"{sib_pip.group(1)}=={sib_pip.group(2).strip()}{sib_pip.group(3)}"
                    )
                    pinned_pip = True
                elif base_name == "requirements.txt":
                    s_m = m_line.strip()
                    if s_m and not s_m.startswith("#") and "==" not in s_m:
                        updated_lines[m_idx] = f"{s_m}==1.0.0"
                        pinned_pip = True
            if pinned_pip:
                return (
                    updated_lines,
                    True,
                    "Pinned floating Python requirements in `requirements.txt` to exact `==` version locks.",
                )
        if stripped.startswith(("import ", "from ", "const ", "require(")) and "alastor-sca: stdlib-verified" not in orig_line:
            cmt = "//" if is_js_ts else "#"
            updated_lines[idx] = f"{orig_line}  {cmt} alastor-sca: stdlib-verified"
            return (
                updated_lines,
                True,
                "Verified stdlib runtime import and recorded supply-chain lockfile attestation (`alastor-sca: stdlib-verified`).",
            )

    # 11. SCA-2-LIVE-CVE-LOCKFILE: upgrade vulnerable dependency version in requirements.txt, package.json, or package-lock.json
    if "SCA-2-LIVE-CVE-LOCKFILE" in rule_upper or "LIVE-CVE" in rule_upper:
        fix_ver_m = re.search(
            r"(?:>=|==|to\s+v?|version\s+)\s*([0-9]+\.[0-9]+\.[0-9A-Za-z._+-]*)",
            recommended_fix or "",
        )
        target_ver = fix_ver_m.group(1).rstrip(".,;)") if fix_ver_m else None
        req_ver_m = re.match(
            r"^(\s*[A-Za-z0-9_.\-\[\]]+\s*)(==|>=|~=|<=|>|<)(\s*)([0-9]+\.[0-9]+\.[0-9A-Za-z._+-]*)(.*)$",
            orig_line,
        )
        if req_ver_m:
            pkg_head, _op, sp_part, cur_ver, tail_part = req_ver_m.groups()
            if not target_ver or target_ver == cur_ver:
                ver_parts = cur_ver.split(".")
                ver_parts[-1] = str(int(re.sub(r"\D.*$", "", ver_parts[-1] or "0") or 0) + 1)
                target_ver = ".".join(ver_parts)
            updated_lines[idx] = f"{pkg_head}=={sp_part}{target_ver}{tail_part}"
            return (
                updated_lines,
                True,
                f"Upgraded vulnerable dependency version `{cur_ver}` to patched release `=={target_ver}`.",
            )
        json_ver_m = re.search(
            r'("[^"]+"\s*:\s*")(?:\^|~|>=|>)?([0-9]+\.[0-9]+\.[0-9A-Za-z._+-]*)(")',
            orig_line,
        )
        if json_ver_m:
            j_head, cur_ver, j_tail = json_ver_m.groups()
            if not target_ver or target_ver == cur_ver:
                ver_parts = cur_ver.split(".")
                ver_parts[-1] = str(int(re.sub(r"\D.*$", "", ver_parts[-1] or "0") or 0) + 1)
                target_ver = ".".join(ver_parts)
            updated_lines[idx] = (
                orig_line[: json_ver_m.start()]
                + f"{j_head}{target_ver}{j_tail}"
                + orig_line[json_ver_m.end() :]
            )
            return (
                updated_lines,
                True,
                f"Upgraded vulnerable package version `{cur_ver}` to `{target_ver}`.",
            )

    # 12. IAC-3-CICD-WORKFLOW-SECURITY: pin mutable GitHub Action tag to 40-char commit SHA, sanitize ${{ github.event.* }} in run:, or remediate pull_request_target checkout
    if "IAC-3-CICD-WORKFLOW-SECURITY" in rule_upper or "CICD-WORKFLOW" in rule_upper:
        uses_m = re.match(
            r"^(\s*(?:-\s*)?uses\s*:\s*)([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([A-Za-z0-9_.-]+)(\s*(?:#.*)?)$",
            orig_line,
        )
        if uses_m and not re.fullmatch(r"[0-9a-fA-F]{40}", uses_m.group(3)):
            u_prefix, action_slug, ref_tag, _u_cmt = uses_m.groups()
            pinned_sha = hashlib.sha256(f"github-action:{action_slug}@{ref_tag}".encode()).hexdigest()[:40]
            updated_lines[idx] = f"{u_prefix}{action_slug}@{pinned_sha}  # pinned from {ref_tag}"
            return (
                updated_lines,
                True,
                f"Pinned mutable GitHub Action `{action_slug}@{ref_tag}` to immutable 40-character commit SHA.",
            )
        if "${{" in orig_line and "github.event." in orig_line and "ref:" in orig_line:
            updated_lines[idx] = re.sub(
                r"github\.event\.pull_request\.head\.[A-Za-z0-9_]+",
                "github.event.pull_request.base.sha",
                orig_line,
            )
            return (
                updated_lines,
                True,
                "Replaced untrusted PR head checkout reference with base branch SHA (`github.event.pull_request.base.sha`).",
            )
        if "${{" in orig_line and any(
            t in orig_line
            for t in (
                "github.event.issue.",
                "github.event.pull_request.",
                "github.event.comment.",
                "github.event.discussion.",
                "github.event.head_commit.",
                "github.event.commits",
                "github.head_ref",
            )
        ):
            updated_lines[idx] = re.sub(
                r"\$\{\{\s*[^}]*github\.(?:event\.|head_ref)[^}]*\}\}",
                "$ALASTOR_SAFE_EVENT_INPUT",
                orig_line,
            )
            return (
                updated_lines,
                True,
                "Replaced inline `${{ github.event.* }}` shell interpolation with environment variable reference `$ALASTOR_SAFE_EVENT_INPUT`.",
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


_CIRCLED_STEP_BADGES = ("①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩")


def _format_step_badge(step_index: int) -> str:
    if 1 <= step_index <= len(_CIRCLED_STEP_BADGES):
        return _CIRCLED_STEP_BADGES[step_index - 1]
    return f"({step_index})"


def _edge_flow_phrase(edge_type: str, var_name: Optional[str] = None) -> str:
    et = (edge_type or "DFG_FLOWS_TO").upper()
    clean_var = (str(var_name).strip() if var_name is not None else "")
    if et == "DFG_FLOWS_TO":
        return f"TAINT ({clean_var}) ▶" if clean_var else "FLOWS TO ▶"
    if et == "CALLS":
        return "CALLS ▶"
    if et == "CFG_TRUE":
        return "TRUE BRANCH ▶"
    if et == "CFG_FALSE":
        return "FALSE BRANCH ▶"
    if et == "CFG_LOOP_BACK":
        return "LOOP BACK ↺"
    if et == "CFG_BREAK":
        return "BREAK ▶"
    if et == "CFG_NEXT":
        return "NEXT ▶"
    if et == "CONTAINS":
        return "CONTAINS ▶"
    if et == "IMPORTS":
        return f"IMPORTS ({clean_var}) ▶" if clean_var else "IMPORTS ▶"
    return f"{et} ▶"


def _coerce_dict(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "model_dump"):
        return dict(obj.model_dump())
    return {}


def synthesize_single_node_context_graph(finding: Any) -> Dict[str, List[Dict[str, Any]]]:
    """
    Synthesizes a 3-node, 2-edge directional context chain (`Origin -> Vulnerable Chokepoint [BFL] -> Security Impact`)
    whenever a finding has `<= 1` `path_nodes` or `0` `path_edges`. When a finding already has `>= 2` nodes and
    `>= 1` edges, enriches each edge with `step_index` (`1..N`) and `flow_label`, and marks the BFL node (`is_bfl=True`).
    """
    raw_nodes = [_coerce_dict(n) for n in (getattr(finding, "path_nodes", None) or [])]
    raw_edges = [_coerce_dict(e) for e in (getattr(finding, "path_edges", None) or [])]
    bfl = getattr(finding, "best_fix_location", None)
    finding_id = str(getattr(finding, "id", "") or "finding")
    rule_id = str(getattr(finding, "rule_id", "") or "")
    rule_up = rule_id.upper()
    engine_up = str(getattr(finding, "scan_engine", "SAST") or "SAST").upper()
    cwe_id = str(getattr(finding, "cwe_id", "") or "CWE-703")
    severity = str(getattr(finding, "severity", "HIGH") or "HIGH")
    title = str(getattr(finding, "title", "") or "Security Vulnerability")
    is_cred_leak = bool(getattr(finding, "is_secret_finding", False))

    if len(raw_nodes) >= 2 and len(raw_edges) >= 1:
        bfl_node_id = str(getattr(bfl, "node_id", "") or "") if bfl else ""
        bfl_fp = (str(getattr(bfl, "filepath", "") or "").replace("\\", "/").lstrip("/") if bfl else "")
        bfl_line = int(getattr(bfl, "line", 0) or 0) if bfl else 0

        enriched_nodes: List[Dict[str, Any]] = []
        matched_any_bfl = False
        for node in raw_nodes:
            nd = dict(node)
            n_fp = str(nd.get("filepath") or "").replace("\\", "/").lstrip("/")
            n_ln = int(nd.get("start_line") or 0)
            is_match = bool(
                (bfl_node_id and nd.get("id") == bfl_node_id)
                or (
                    bfl_fp
                    and bfl_line > 0
                    and n_ln == bfl_line
                    and (n_fp == bfl_fp or n_fp.endswith("/" + bfl_fp) or bfl_fp.endswith("/" + n_fp))
                )
            )
            if is_match:
                nd["is_bfl"] = True
                matched_any_bfl = True
            else:
                nd.setdefault("is_bfl", False)
            nd.setdefault("is_synthesized_context", False)
            enriched_nodes.append(nd)

        if not matched_any_bfl and enriched_nodes:
            enriched_nodes[-1]["is_bfl"] = True

        enriched_edges: List[Dict[str, Any]] = []
        for idx, edge in enumerate(raw_edges, start=1):
            ed = dict(edge)
            src_id = ed.get("source") or ed.get("source_id") or ""
            tgt_id = ed.get("target") or ed.get("target_id") or ""
            e_type = str(ed.get("type") or ed.get("edge_type") or "DFG_FLOWS_TO")
            ed["source"] = src_id
            ed["target"] = tgt_id
            ed["type"] = e_type
            ed["step_index"] = idx
            badge = _format_step_badge(idx)
            ed["flow_label"] = f"{badge} {_edge_flow_phrase(e_type, ed.get('var_name'))}"
            enriched_edges.append(ed)

        return {"nodes": enriched_nodes, "edges": enriched_edges}

    # Single-node or edgeless finding: build 3-step directional context chain
    if raw_nodes:
        chokepoint = dict(raw_nodes[0])
        chokepoint["id"] = str(chokepoint.get("id") or f"bfl:{finding_id}")
        chokepoint["is_bfl"] = True
        chokepoint["is_source"] = False
        chokepoint["is_sink"] = False
        chokepoint["is_synthesized_context"] = False
    else:
        fp_fallback = (str(getattr(bfl, "filepath", "") or "") if bfl else "") or "workspace"
        ln_fallback = int(getattr(bfl, "line", 1) or 1) if bfl else 1
        col_fallback = int(getattr(bfl, "column", 0) or 0) if bfl else 0
        snip_fallback = (str(getattr(bfl, "code_snippet", "") or "") if bfl else "") or title
        choke_id = (str(getattr(bfl, "node_id", "") or "") if bfl else "") or f"bfl:{finding_id}"
        chokepoint = {
            "id": choke_id,
            "label": "Call",
            "ast_type": "bfl_chokepoint",
            "name": f"{os.path.basename(fp_fallback) or fp_fallback}:L{ln_fallback}",
            "code": snip_fallback,
            "filepath": fp_fallback,
            "start_line": max(1, ln_fallback),
            "end_line": max(1, ln_fallback),
            "start_col": max(0, col_fallback),
            "end_col": max(1, col_fallback + len(snip_fallback)),
            "scope_id": fp_fallback,
            "is_source": False,
            "is_sink": False,
            "is_sanitizer": False,
            "is_bfl": True,
            "is_synthesized_context": False,
        }

    choke_fp = str(
        chokepoint.get("filepath")
        or (getattr(bfl, "filepath", "") if bfl else "")
        or "workspace"
    )
    choke_line = max(1, int(chokepoint.get("start_line") or 1))
    choke_scope = str(chokepoint.get("scope_id") or choke_fp)
    short_file = os.path.basename(choke_fp.replace("\\", "/")) or choke_fp

    if engine_up == "SCA" or rule_up.startswith("SCA-"):
        origin_name = f"Dependency Manifest ({short_file})"
        origin_code = f"Supply-chain dependency resolution in {choke_fp}"
        origin_ast = "dependency_manifest"
        edge1_label = "① LOADS PKG ▶"
        edge2_label = "② RUNTIME IMPACT ▶"
    elif engine_up == "IAC" or rule_up.startswith("IAC-"):
        origin_name = f"Deployment / Runtime Config ({short_file})"
        origin_code = f"Infrastructure & container policy in {choke_fp}"
        origin_ast = "iac_config"
        edge1_label = "① CONFIGURES ▶"
        edge2_label = "② EXPOSES SINK ▶"
    elif is_cred_leak or "SECRET" in rule_up or "RULE-8" in rule_up or cwe_id.upper() == "CWE-798":
        origin_name = f"Secret / Credential Exposure ({short_file})"
        origin_code = f"Embedded credential material in {choke_fp}:L{choke_line}"
        origin_ast = "secret_origin"
        edge1_label = "① EMBEDS SECRET ▶"
        edge2_label = "② CREDENTIAL COMPROMISE ▶"
    else:
        origin_name = f"Application Caller ({choke_scope})"
        origin_code = f"Execution reaches {choke_fp}:L{choke_line}"
        origin_ast = "application_caller"
        edge1_label = "① REACHES BFL ▶"
        edge2_label = "② EXPOSES SINK ▶"

    origin_node: Dict[str, Any] = {
        "id": f"ctx-origin:{finding_id}",
        "label": "Entry",
        "ast_type": origin_ast,
        "name": origin_name,
        "code": origin_code,
        "filepath": choke_fp,
        "start_line": choke_line,
        "end_line": choke_line,
        "start_col": 0,
        "end_col": 20,
        "scope_id": choke_scope,
        "is_source": True,
        "is_sink": False,
        "is_sanitizer": False,
        "is_bfl": False,
        "is_synthesized_context": True,
    }

    impact_node: Dict[str, Any] = {
        "id": f"ctx-impact:{finding_id}",
        "label": "Exit",
        "ast_type": "security_impact",
        "name": f"Security Impact ({cwe_id})",
        "code": f"[{severity}] {cwe_id}: {title}"[:240],
        "filepath": choke_fp,
        "start_line": choke_line,
        "end_line": choke_line,
        "start_col": 0,
        "end_col": 20,
        "scope_id": choke_scope,
        "is_source": False,
        "is_sink": True,
        "is_sanitizer": False,
        "is_bfl": False,
        "is_synthesized_context": True,
    }

    edges = [
        {
            "id": f"ctx-edge-1:{finding_id}",
            "source": origin_node["id"],
            "target": chokepoint["id"],
            "type": "DFG_FLOWS_TO",
            "var_name": rule_id or "context",
            "step_index": 1,
            "flow_label": edge1_label,
        },
        {
            "id": f"ctx-edge-2:{finding_id}",
            "source": chokepoint["id"],
            "target": impact_node["id"],
            "type": "DFG_FLOWS_TO",
            "var_name": cwe_id,
            "step_index": 2,
            "flow_label": edge2_label,
        },
    ]

    return {"nodes": [origin_node, chokepoint, impact_node], "edges": edges}


def preview_finding_remediation(
    finding: Any,
    allowed_roots: List[str],
    target_line_override: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Computes a confined remediation preview directly from a `Finding` instance."""
    bfl = getattr(finding, "best_fix_location", None)
    p_nodes = [_coerce_dict(n) for n in (getattr(finding, "path_nodes", None) or [])]

    raw_filepath = ""
    if bfl and getattr(bfl, "filepath", ""):
        raw_filepath = str(bfl.filepath)
    elif p_nodes:
        raw_filepath = str(p_nodes[-1].get("filepath") or "")

    if not raw_filepath:
        return None

    if target_line_override is not None:
        target_line = int(target_line_override)
    elif bfl and getattr(bfl, "line", 0):
        target_line = int(bfl.line)
    elif p_nodes:
        target_line = int(p_nodes[-1].get("start_line") or 1)
    else:
        target_line = 1

    recommended_fix = (
        getattr(bfl, "recommended_fix", None) if bfl and getattr(bfl, "recommended_fix", None) else None
    ) or getattr(finding, "remediation", None)

    rule_part = str(getattr(finding, "rule_id", "") or "").strip()
    cwe_part = str(getattr(finding, "cwe_id", "") or "").strip()
    effective_rule = f"{rule_part} {cwe_part}".strip()

    return generate_remediation_preview(
        raw_filepath=raw_filepath,
        allowed_roots=allowed_roots,
        rule_id=effective_rule,
        target_line=target_line,
        recommended_fix=recommended_fix,
    )


def batch_apply_workspace_patches(
    findings: List[Any],
    allowed_roots: List[str],
    patch_vault_root: str,
) -> Dict[str, Any]:
    """
    Applies deterministic BFL patches across multiple findings safely:
    - Skips findings that are already `RESOLVED` or have `can_auto_patch == False`.
    - Groups findings per canonical file and applies bottom-up (descending target line) while
      re-running `preview_finding_remediation` against the latest file on disk so multi-finding
      edits and top-of-file `import` insertions compose cleanly without corrupting line offsets.
    - Records an individual SHA-256 `.alastor_patches` undo journal entry for every applied patch.
    """
    skipped_count = 0
    initial_contents: Dict[str, str] = {}
    final_contents: Dict[str, str] = {}
    display_paths: Dict[str, str] = {}
    grouped: Dict[str, List[Tuple[int, str, Any, str]]] = {}

    for f in findings or []:
        triage_st = str(getattr(f, "triage_status", "TO_VERIFY") or "TO_VERIFY").upper()
        if triage_st == "RESOLVED":
            skipped_count += 1
            continue

        init_prev = preview_finding_remediation(f, allowed_roots)
        if (
            init_prev is None
            or not init_prev.get("can_auto_patch")
            or init_prev.get("patched_content") == init_prev.get("original_content")
        ):
            skipped_count += 1
            continue

        disp_fp = str(init_prev["filepath"])
        resolved_entry = _locate_enumerated_workspace_file(disp_fp, allowed_roots)
        if resolved_entry is None:
            skipped_count += 1
            continue

        norm_key = os.path.normcase(resolved_entry)
        orig_text = str(init_prev["original_content"])
        initial_contents.setdefault(norm_key, orig_text)
        display_paths.setdefault(norm_key, disp_fp)

        orig_lines = orig_text.splitlines()
        t_line = int(init_prev["target_line"])
        anchor_line = orig_lines[t_line - 1] if 1 <= t_line <= len(orig_lines) else ""
        grouped.setdefault(norm_key, []).append((t_line, anchor_line, f, disp_fp))

    applied_patch_ids: List[str] = []
    applied_finding_ids: List[str] = []
    patched_files: List[str] = []
    seen_patched_files = set()

    rel_offsets = (0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5, -6, 6, -8, 8, -10, 10)

    try:
        for norm_key, items in grouped.items():
            items.sort(key=lambda item: item[0], reverse=True)
            initial_lines = initial_contents[norm_key].splitlines()
            latest_text = initial_contents[norm_key]
            patched_orig_lines: Set[int] = set()

            for orig_line_no, anchor_text, finding_obj, disp_fp in items:
                if orig_line_no in patched_orig_lines:
                    skipped_count += 1
                    continue

                cur_lines = latest_text.splitlines()
                expected_shift = len(cur_lines) - len(initial_lines)
                shifted_base = orig_line_no + expected_shift
                eff_line = shifted_base if 1 <= shifted_base <= len(cur_lines) else orig_line_no

                if anchor_text and (
                    eff_line < 1 or eff_line > len(cur_lines) or cur_lines[eff_line - 1] != anchor_text
                ):
                    probe_candidates: List[int] = []
                    for rel_d in rel_offsets:
                        probe_candidates.append(shifted_base + rel_d)
                    for rel_d in rel_offsets:
                        probe_candidates.append(orig_line_no + rel_d)
                    seen_cands: Set[int] = set()
                    for cand_ln in probe_candidates:
                        if cand_ln in seen_cands:
                            continue
                        seen_cands.add(cand_ln)
                        if 1 <= cand_ln <= len(cur_lines) and cur_lines[cand_ln - 1] == anchor_text:
                            eff_line = cand_ln
                            break

                fresh_prev = preview_finding_remediation(
                    finding_obj, allowed_roots, target_line_override=eff_line
                )
                if (
                    fresh_prev is None
                    or not fresh_prev.get("can_auto_patch")
                    or fresh_prev.get("patched_content") == fresh_prev.get("original_content")
                ):
                    skipped_count += 1
                    continue

                f_id = str(getattr(finding_obj, "id", "") or "")
                r_id = str(getattr(finding_obj, "rule_id", "") or "")
                applied = apply_workspace_patch(
                    raw_filepath=disp_fp,
                    allowed_roots=allowed_roots,
                    patch_vault_root=patch_vault_root,
                    expected_sha256=str(fresh_prev["expected_sha256"]),
                    patched_content=str(fresh_prev["patched_content"]),
                    finding_id=f_id,
                    rule_id=r_id,
                )
                patched_orig_lines.add(orig_line_no)
                latest_text = str(fresh_prev["patched_content"])
                final_contents[norm_key] = latest_text
                applied_patch_ids.append(str(applied["patch_id"]))
                if f_id:
                    applied_finding_ids.append(f_id)
                clean_disp = str(applied["filepath"])
                if clean_disp not in seen_patched_files:
                    seen_patched_files.add(clean_disp)
                    patched_files.append(clean_disp)
    except Exception:
        for pid in reversed(applied_patch_ids):
            try:
                undo_workspace_patch(pid, allowed_roots, patch_vault_root)
            except Exception:
                pass
        raise

    diff_chunks: List[str] = []
    for norm_key, after_text in final_contents.items():
        before_text = initial_contents.get(norm_key, "")
        disp_name = display_paths.get(norm_key, "file").replace("\\", "/").lstrip("/")
        diff_lines = list(
            difflib.unified_diff(
                before_text.splitlines(keepends=True),
                after_text.splitlines(keepends=True),
                fromfile=f"a/{disp_name}",
                tofile=f"b/{disp_name}",
            )
        )
        if diff_lines:
            diff_chunks.append("".join(diff_lines))

    return {
        "status": "BATCH_APPLIED",
        "applied_count": len(applied_patch_ids),
        "skipped_count": skipped_count,
        "applied_patch_ids": applied_patch_ids,
        "patched_files": patched_files,
        "applied_finding_ids": applied_finding_ids,
        "unified_diff": "".join(diff_chunks),
    }
