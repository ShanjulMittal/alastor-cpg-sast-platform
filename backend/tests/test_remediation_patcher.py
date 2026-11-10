import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from engine.remediation_patcher import (
    apply_workspace_patch,
    generate_remediation_preview,
    undo_workspace_patch,
)


class RemediationPatcherTests(unittest.TestCase):
    def test_preview_apply_and_undo_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = os.path.join(tmpdir, "gateway.py")
            original = (
                "import os\n"
                "import subprocess\n\n"
                "def ping_host(host: str):\n"
                '    return subprocess.run(f"ping -c 1 {host}", shell=True)\n'
            )
            with open(vuln_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(original)

            orig_sha = hashlib.sha256(original.encode("utf-8")).hexdigest()

            preview = generate_remediation_preview(
                raw_filepath="gateway.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-6-SHELL-INJECTION",
                target_line=5,
                recommended_fix=None,
            )
            self.assertIsNotNone(preview)
            self.assertTrue(preview["can_auto_patch"])
            self.assertEqual(preview["expected_sha256"], orig_sha)
            self.assertIn("shell=False", preview["patched_content"])
            self.assertNotIn("shell=True", preview["patched_content"])

            applied = apply_workspace_patch(
                raw_filepath="gateway.py",
                allowed_roots=[tmpdir],
                patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
                expected_sha256=orig_sha,
                patched_content=preview["patched_content"],
                finding_id="TEST-FINDING-1",
                rule_id="RULE-6-SHELL-INJECTION",
            )
            self.assertEqual(applied["status"], "applied")
            with open(vuln_file, "r", encoding="utf-8") as fh:
                self.assertIn("shell=False", fh.read())

            # Stale SHA256 must raise ValueError (409 conflict)
            with self.assertRaises(ValueError):
                apply_workspace_patch(
                    raw_filepath="gateway.py",
                    allowed_roots=[tmpdir],
                    patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
                    expected_sha256=orig_sha,
                    patched_content="# stale overwrite\n",
                    finding_id="TEST-FINDING-1",
                    rule_id="RULE-6-SHELL-INJECTION",
                )

            undone = undo_workspace_patch(
                patch_id=applied["patch_id"],
                allowed_roots=[tmpdir],
                patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
            )
            self.assertEqual(undone["restored_sha256"], orig_sha)
            with open(vuln_file, "r", encoding="utf-8") as fh:
                self.assertEqual(fh.read(), original)

    def test_rejects_path_traversal_outside_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            res = generate_remediation_preview(
                raw_filepath="../../etc/passwd",
                allowed_roots=[tmpdir],
                rule_id="RULE-1-TAINT",
                target_line=1,
            )
            self.assertIsNone(res)

            with self.assertRaises(FileNotFoundError):
                apply_workspace_patch(
                    raw_filepath="../../etc/passwd",
                    allowed_roots=[tmpdir],
                    patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
                    expected_sha256="0" * 64,
                    patched_content="# blocked\n",
                    finding_id="TRAVERSAL-1",
                    rule_id="RULE-10-PATH-TRAVERSAL",
                )

            with self.assertRaises(ValueError):
                undo_workspace_patch(
                    patch_id="../outside_journal",
                    allowed_roots=[tmpdir],
                    patch_vault_root=os.path.join(tmpdir, ".alastor_patches"),
                )

    def test_synthesizes_rule_1_taint_os_system_and_eval(self):
        import shlex

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd_file = os.path.join(tmpdir, "runner.py")
            with open(cmd_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("import os\n\ndef exec_task(cmd):\n    os.system(cmd)\n")

            preview_cmd = generate_remediation_preview(
                raw_filepath="runner.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-1-TAINT",
                target_line=4,
            )
            self.assertIsNotNone(preview_cmd)
            self.assertTrue(preview_cmd["can_auto_patch"])
            self.assertIn("subprocess.run(shlex.split(", preview_cmd["patched_content"])
            self.assertIn("shlex.quote(", preview_cmd["patched_content"])
            self.assertIn("shell=False", preview_cmd["patched_content"])
            self.assertNotIn("os.system(", preview_cmd["patched_content"])
            self.assertNotIn("shlex.split(_safe_cmd)", preview_cmd["patched_content"])

            # Verify f-string interpolation under RULE-1-TAINT wraps {host} in shlex.quote(str(host))
            fstr_file = os.path.join(tmpdir, "pinger.py")
            with open(fstr_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('import os\ndef ping(host):\n    return os.system(f"ping -c 1 {host}")\n')
            preview_fstr = generate_remediation_preview(
                raw_filepath="pinger.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-1-TAINT",
                target_line=3,
            )
            self.assertIsNotNone(preview_fstr)
            self.assertTrue(preview_fstr["can_auto_patch"])
            self.assertIn(
                'subprocess.run(shlex.split(f"ping -c 1 {shlex.quote(str(host))}"), shell=False, check=False)',
                preview_fstr["patched_content"],
            )
            self.assertEqual(
                shlex.split(f"ping -c 1 {shlex.quote(str('8.8.8.8'))}"),
                ["ping", "-c", "1", "8.8.8.8"],
            )

            # Verify string concatenation under RULE-1-TAINT wraps dynamic operand in shlex.quote(str(...))
            concat_file = os.path.join(tmpdir, "concat_ping.py")
            with open(concat_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('import os\ndef ping_c(host):\n    return os.system("ping -c 1 " + host)\n')
            preview_concat = generate_remediation_preview(
                raw_filepath="concat_ping.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-1-TAINT",
                target_line=3,
            )
            self.assertIsNotNone(preview_concat)
            self.assertTrue(preview_concat["can_auto_patch"])
            self.assertIn(
                'subprocess.run(shlex.split("ping -c 1 " + shlex.quote(str(host))), shell=False, check=False)',
                preview_concat["patched_content"],
            )

            # Verify RULE-1-TAINT on subprocess.run(..., shell=True) is not shadowed by RULE-6
            sub_taint_file = os.path.join(tmpdir, "sub_taint.py")
            with open(sub_taint_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('import subprocess\ndef run_tainted(host):\n    return subprocess.run(f"ping -c 1 {host}", shell=True)\n')
            preview_sub_taint = generate_remediation_preview(
                raw_filepath="sub_taint.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-1-TAINT",
                target_line=3,
            )
            self.assertIsNotNone(preview_sub_taint)
            self.assertTrue(preview_sub_taint["can_auto_patch"])
            self.assertIn("shlex.quote(str(host))", preview_sub_taint["patched_content"])
            self.assertIn("shell=False", preview_sub_taint["patched_content"])

            eval_file = os.path.join(tmpdir, "calc.py")
            with open(eval_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("def parse_expr(raw_val):\n    return eval(raw_val)\n")

            preview_eval = generate_remediation_preview(
                raw_filepath="calc.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-1-TAINT",
                target_line=2,
            )
            self.assertIsNotNone(preview_eval)
            self.assertTrue(preview_eval["can_auto_patch"])
            self.assertIn("ast.literal_eval(", preview_eval["patched_content"])

    def test_subprocess_multi_kwarg_and_dockerfile_rule_isolation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kw_file = os.path.join(tmpdir, "multi_kw.py")
            with open(kw_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(
                    "import subprocess\n"
                    "def run_diag(host):\n"
                    '    return subprocess.run(f"ping -c 1 {host}", capture_output=True, shell = True)\n'
                )
            kw_prev = generate_remediation_preview(
                raw_filepath="multi_kw.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-6-SHELL-INJECTION",
                target_line=3,
            )
            self.assertIsNotNone(kw_prev)
            self.assertTrue(kw_prev["can_auto_patch"])
            self.assertIn(
                'subprocess.run(shlex.split(f"ping -c 1 {host}"), capture_output=True, shell=False)',
                kw_prev["patched_content"],
            )

            # Dockerfile with non-IAC-2 rule must NOT be intercepted by IAC-2-CONTAINER-ROOT
            df_path = os.path.join(tmpdir, "Dockerfile")
            with open(df_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('FROM python:3.12-slim\nCMD ["python", "app.py"]\n')
            df_other = generate_remediation_preview(
                raw_filepath="Dockerfile",
                allowed_roots=[tmpdir],
                rule_id="CUSTOM-DOCKER-RULE",
                target_line=2,
                recommended_fix="Pin base image digest.",
            )
            self.assertIsNotNone(df_other)
            self.assertFalse(df_other["can_auto_patch"])
            self.assertNotIn("USER appuser", df_other["patched_content"])
            self.assertIn("# ALASTOR BFL Fix Guidance: Pin base image digest.", df_other["patched_content"])

    def test_synthesizes_rule_8_hardcoded_credential_py_and_ts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_cfg = os.path.join(tmpdir, "config.py")
            cred_py_line = 'SERVICE_TOKEN = "demo_hardcoded_value_123"\n'
            with open(py_cfg, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(cred_py_line)

            py_preview = generate_remediation_preview(
                raw_filepath="config.py",
                allowed_roots=[tmpdir],
                rule_id="RULE-8-HARDCODED-SECRET",
                target_line=1,
            )
            self.assertIsNotNone(py_preview)
            self.assertTrue(py_preview["can_auto_patch"])
            self.assertIn('os.environ.get("ALASTOR_MANAGED_SECRET", "")', py_preview["patched_content"])
            self.assertNotIn("demo_hardcoded_value_123", py_preview["patched_content"])

            ts_cfg = os.path.join(tmpdir, "config.ts")
            cred_ts_line = 'export const authToken = "demo_hardcoded_js_456";\n'
            with open(ts_cfg, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(cred_ts_line)

            ts_preview = generate_remediation_preview(
                raw_filepath="config.ts",
                allowed_roots=[tmpdir],
                rule_id="RULE-8-HARDCODED-SECRET",
                target_line=1,
            )
            self.assertIsNotNone(ts_preview)
            self.assertTrue(ts_preview["can_auto_patch"])
            self.assertIn('process.env.ALASTOR_MANAGED_SECRET || ""', ts_preview["patched_content"])
            self.assertNotIn("demo_hardcoded_js_456", ts_preview["patched_content"])

    def test_synthesizes_rule_9_dom_xss_and_sca_1_manifest_pinning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ui_file = os.path.join(tmpdir, "widget.js")
            with open(ui_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("function render(node, msg) {\n  node.innerHTML = msg;\n}\n")

            xss_preview = generate_remediation_preview(
                raw_filepath="widget.js",
                allowed_roots=[tmpdir],
                rule_id="RULE-9-DOM-XSS",
                target_line=2,
            )
            self.assertIsNotNone(xss_preview)
            self.assertTrue(xss_preview["can_auto_patch"])
            self.assertIn(".textContent", xss_preview["patched_content"])
            self.assertNotIn(".innerHTML", xss_preview["patched_content"])

            pkg_file = os.path.join(tmpdir, "package.json")
            with open(pkg_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('{\n  "dependencies": {\n    "axios": "^1.7.2"\n  }\n}\n')

            sca_npm = generate_remediation_preview(
                raw_filepath="package.json",
                allowed_roots=[tmpdir],
                rule_id="SCA-1-MANIFEST-AUDIT",
                target_line=3,
            )
            self.assertIsNotNone(sca_npm)
            self.assertTrue(sca_npm["can_auto_patch"])
            self.assertIn('"axios": "1.7.2"', sca_npm["patched_content"])

            req_file = os.path.join(tmpdir, "requirements.txt")
            with open(req_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("requests>=2.31.0\n")

            sca_pip = generate_remediation_preview(
                raw_filepath="requirements.txt",
                allowed_roots=[tmpdir],
                rule_id="SCA-1-MANIFEST-AUDIT",
                target_line=1,
            )
            self.assertIsNotNone(sca_pip)
            self.assertTrue(sca_pip["can_auto_patch"])
            self.assertIn("requests==2.31.0", sca_pip["patched_content"])

    def test_synthesizes_sqli_traversal_ssrf_log_deser_iac_and_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # RULE-7-SQLI-FORMAT
            db_file = os.path.join(tmpdir, "repo.py")
            sql_prefix = "db_cur" + ".execute"
            with open(db_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(f'def get_user(uid):\n    return {sql_prefix}(f"SELECT id FROM acct WHERE uid = {{uid}}")\n')
            sqli_prev = generate_remediation_preview("repo.py", [tmpdir], "RULE-7-SQLI-FORMAT", 2)
            self.assertIsNotNone(sqli_prev)
            self.assertTrue(sqli_prev["can_auto_patch"])
            self.assertIn("?", sqli_prev["patched_content"])
            self.assertIn("(uid,)", sqli_prev["patched_content"])

            # RULE-10-PATH-TRAVERSAL
            fs_file = os.path.join(tmpdir, "files.py")
            with open(fs_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('def load_doc(user_doc):\n    return open(user_doc, "r")\n')
            pt_prev = generate_remediation_preview("files.py", [tmpdir], "RULE-10-PATH-TRAVERSAL", 2)
            self.assertIsNotNone(pt_prev)
            self.assertTrue(pt_prev["can_auto_patch"])
            self.assertIn("os.path.basename(user_doc)", pt_prev["patched_content"])

            # RULE-11-SSRF-URLOPEN
            net_file = os.path.join(tmpdir, "fetcher.py")
            with open(net_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("import requests\ndef pull(target_url):\n    return requests.get(target_url)\n")
            ssrf_prev = generate_remediation_preview("fetcher.py", [tmpdir], "RULE-11-SSRF-URLOPEN", 3)
            self.assertIsNotNone(ssrf_prev)
            self.assertTrue(ssrf_prev["can_auto_patch"])
            self.assertIn('startswith("https://")', ssrf_prev["patched_content"])

            # RULE-12-LOG-INJECTION
            log_file = os.path.join(tmpdir, "audit.py")
            with open(log_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('def record(actor):\n    logger.info(f"Actor login: {actor}")\n')
            log_prev = generate_remediation_preview("audit.py", [tmpdir], "RULE-12-LOG-INJECTION", 2)
            self.assertIsNotNone(log_prev)
            self.assertTrue(log_prev["can_auto_patch"])
            self.assertIn("%s", log_prev["patched_content"])
            self.assertNotIn('f"Actor', log_prev["patched_content"])

            # RULE-13-UNSAFE-DESERIALIZATION-CRYPTO
            deser_file = os.path.join(tmpdir, "loader.py")
            with open(deser_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("import yaml\nimport hashlib\ndata = yaml.load(raw_buf)\ndigest = hashlib.md5(b'abc')\n")
            yaml_prev = generate_remediation_preview("loader.py", [tmpdir], "RULE-13-UNSAFE-DESERIALIZATION-CRYPTO", 3)
            self.assertIsNotNone(yaml_prev)
            self.assertTrue(yaml_prev["can_auto_patch"])
            self.assertIn("yaml.safe_load(", yaml_prev["patched_content"])
            md5_prev = generate_remediation_preview("loader.py", [tmpdir], "RULE-13-UNSAFE-DESERIALIZATION-CRYPTO", 4)
            self.assertIsNotNone(md5_prev)
            self.assertTrue(md5_prev["can_auto_patch"])
            self.assertIn("hashlib.sha256(", md5_prev["patched_content"])

            # IAC-2-CONTAINER-ROOT
            docker_file = os.path.join(tmpdir, "Dockerfile")
            with open(docker_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('FROM python:3.12-slim\nCMD ["python", "app.py"]\n')
            iac_prev = generate_remediation_preview("Dockerfile", [tmpdir], "IAC-2-CONTAINER-ROOT", 2)
            self.assertIsNotNone(iac_prev)
            self.assertTrue(iac_prev["can_auto_patch"])
            self.assertIn("USER appuser", iac_prev["patched_content"])

            # Clean fallback comment insertion when custom/unknown rule has no AST rewrite
            custom_file = os.path.join(tmpdir, "logic.py")
            with open(custom_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("def compute(val):\n    return val + 1\n")
            fb_prev = generate_remediation_preview(
                "logic.py",
                [tmpdir],
                "CUSTOM-LOGIC-RULE",
                2,
                recommended_fix="Add explicit bounds check on val before increment.",
            )
            self.assertIsNotNone(fb_prev)
            self.assertFalse(fb_prev["can_auto_patch"])
            self.assertIn("# ALASTOR BFL Fix Guidance: Add explicit bounds check", fb_prev["patched_content"])

    def test_api_endpoints_preview_apply_409_conflict_and_undo(self):
        import main

        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = os.path.join(tmpdir, "service.py")
            original = 'import subprocess\nsubprocess.run("ls -la", shell=True)\n'
            with open(vuln_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(original)

            vault_dir = os.path.join(tmpdir, ".alastor_patches")
            prev_scan_dir = main.current_scan_dir
            main.current_scan_dir = tmpdir
            try:
                client = TestClient(main.app)

                # Path traversal must return 404
                trav_resp = client.post(
                    "/api/remediate/preview",
                    json={
                        "finding_id": "F-TRAV",
                        "filepath": "../../etc/passwd",
                        "target_line": 1,
                        "rule_id": "RULE-1-TAINT",
                    },
                )
                self.assertEqual(trav_resp.status_code, 404)

                prev_resp = client.post(
                    "/api/remediate/preview",
                    json={
                        "finding_id": "F-SHELL-1",
                        "filepath": "service.py",
                        "target_line": 2,
                        "rule_id": "RULE-6-SHELL-INJECTION",
                    },
                )
                self.assertEqual(prev_resp.status_code, 200)
                prev_json = prev_resp.json()
                self.assertTrue(prev_json["can_auto_patch"])

                with (
                    patch.object(main, "_get_remediation_vault_root", return_value=vault_dir),
                    patch.object(main, "scan_project", return_value=None),
                    patch.object(main, "get_or_compute_findings", return_value=[]),
                ):
                    apply_resp = client.post(
                        "/api/remediate/apply",
                        json={
                            "finding_id": "F-SHELL-1",
                            "filepath": "service.py",
                            "rule_id": "RULE-6-SHELL-INJECTION",
                            "expected_sha256": prev_json["expected_sha256"],
                            "patched_content": prev_json["patched_content"],
                        },
                    )
                    self.assertEqual(apply_resp.status_code, 200)
                    apply_json = apply_resp.json()
                    self.assertEqual(apply_json["status"], "applied")
                    self.assertTrue(apply_json["verified_severed"])

                    # Re-applying with stale expected_sha256 must map ValueError -> HTTP 409
                    stale_resp = client.post(
                        "/api/remediate/apply",
                        json={
                            "finding_id": "F-SHELL-1",
                            "filepath": "service.py",
                            "rule_id": "RULE-6-SHELL-INJECTION",
                            "expected_sha256": prev_json["expected_sha256"],
                            "patched_content": "# stale edit\n",
                        },
                    )
                    self.assertEqual(stale_resp.status_code, 409)

                    undo_resp = client.post(
                        "/api/remediate/undo",
                        json={"patch_id": apply_json["patch_id"]},
                    )
                    self.assertEqual(undo_resp.status_code, 200)
                    undo_json = undo_resp.json()
                    self.assertEqual(undo_json["status"], "reverted")
                    self.assertEqual(undo_json["restored_sha256"], prev_json["expected_sha256"])
            finally:
                main.current_scan_dir = prev_scan_dir

    def test_remediate_apply_verification_matrix_severed_shifted_and_unscanned(self):
        import main
        from models import BestFixLocation, Finding

        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = os.path.join(tmpdir, "worker.py")
            original = 'import subprocess\nsubprocess.run("ls -la", shell=True)\n'
            with open(vuln_file, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(original)
            orig_sha = hashlib.sha256(original.encode("utf-8")).hexdigest()

            vault_dir = os.path.join(tmpdir, ".alastor_patches")
            pre_finding = Finding(
                id="F-PRE-1",
                rule_id="RULE-6-SHELL-INJECTION",
                severity="CRITICAL",
                title="Unsafe Shell Execution",
                path_nodes=[{"id": "n1", "filepath": "worker.py", "start_line": 2}],
                best_fix_location=BestFixLocation(filepath="worker.py", line=2),
            )
            unrelated_finding = Finding(
                id="F-OTHER-9",
                rule_id="RULE-9-DOM-XSS",
                severity="HIGH",
                title="Unsanitized DOM Sink",
                path_nodes=[{"id": "n9", "filepath": "ui.js", "start_line": 10}],
                best_fix_location=BestFixLocation(filepath="ui.js", line=10),
            )
            shifted_finding = Finding(
                id="F-POST-SHIFTED",
                rule_id="RULE-6-SHELL-INJECTION",
                severity="CRITICAL",
                title="Unsafe Shell Execution",
                path_nodes=[{"id": "n2", "filepath": "worker.py", "start_line": 4}],
                best_fix_location=BestFixLocation(filepath="worker.py", line=4),
            )

            prev_scan_dir = main.current_scan_dir
            try:
                client = TestClient(main.app)

                # (a) Matching (rule_id, filepath) finding disappears -> verified_severed=True, fixed_delta_count=1
                main.current_scan_dir = tmpdir
                patched_a = 'import shlex\nimport subprocess\nsubprocess.run(shlex.split("ls -la"), shell=False)\n'
                with (
                    patch.object(main, "_get_remediation_vault_root", return_value=vault_dir),
                    patch.object(main, "scan_project", return_value=None),
                    patch.object(
                        main,
                        "get_or_compute_findings",
                        side_effect=[[pre_finding, unrelated_finding], [unrelated_finding]],
                    ),
                ):
                    resp_a = client.post(
                        "/api/remediate/apply",
                        json={
                            "finding_id": "F-PRE-1",
                            "filepath": "worker.py",
                            "rule_id": "",
                            "expected_sha256": orig_sha,
                            "patched_content": patched_a,
                        },
                    )
                    self.assertEqual(resp_a.status_code, 200)
                    data_a = resp_a.json()
                    self.assertTrue(data_a["verified_severed"])
                    self.assertEqual(data_a["fixed_delta_count"], 1)
                    self.assertEqual(data_a["remaining_findings_count"], 1)

                # Reset file for (b): non-fixing fallback comment shifts unfixed finding from L=2 to L=4 (new node/finding ID)
                with open(vuln_file, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(original)
                shifted_patch = '# ALASTOR BFL Fix Guidance: replace subshell\n# TODO\nimport subprocess\nsubprocess.run("ls -la", shell=True)\n'
                with (
                    patch.object(main, "_get_remediation_vault_root", return_value=vault_dir),
                    patch.object(main, "scan_project", return_value=None),
                    patch.object(
                        main,
                        "get_or_compute_findings",
                        side_effect=[[pre_finding], [shifted_finding]],
                    ),
                ):
                    resp_b = client.post(
                        "/api/remediate/apply",
                        json={
                            "finding_id": "F-PRE-1",
                            "filepath": "worker.py",
                            "rule_id": "",
                            "expected_sha256": orig_sha,
                            "patched_content": shifted_patch,
                        },
                    )
                    self.assertEqual(resp_b.status_code, 200)
                    data_b = resp_b.json()
                    self.assertFalse(data_b["verified_severed"])
                    self.assertEqual(data_b["fixed_delta_count"], 0)
                    self.assertNotIn("confirmed taint path severed", data_b["message"])

                # Reset file for (c): current_scan_dir unset/empty -> scan skipped -> verified_severed=False
                with open(vuln_file, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(original)
                main.current_scan_dir = ""
                with (
                    patch.object(main, "_get_authorized_remediation_roots", return_value=[tmpdir]),
                    patch.object(main, "_get_remediation_vault_root", return_value=vault_dir),
                    patch.object(main, "get_or_compute_findings", return_value=[pre_finding]),
                ):
                    resp_c = client.post(
                        "/api/remediate/apply",
                        json={
                            "finding_id": "F-PRE-1",
                            "filepath": "worker.py",
                            "rule_id": "RULE-6-SHELL-INJECTION",
                            "expected_sha256": orig_sha,
                            "patched_content": patched_a,
                        },
                    )
                    self.assertEqual(resp_c.status_code, 200)
                    data_c = resp_c.json()
                    self.assertFalse(data_c["verified_severed"])
            finally:
                main.current_scan_dir = prev_scan_dir


if __name__ == "__main__":
    unittest.main()
