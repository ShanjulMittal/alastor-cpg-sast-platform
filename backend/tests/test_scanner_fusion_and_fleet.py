"""
TDD Suite for ALASTOR v5.0 Pillar 4 Task 2:
- Universal 6-Format Scanner Fusion (`engine/scanner_fusion_engine.py`)
- CSV Batch Fleet Runner & App-Group Go-Live Rollups (`engine/fleet_runner.py`)
"""
from __future__ import annotations

import os
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from compiler.ast_parser import ASTNormalizer
from compiler.scanner import scan_directory_with_telemetry
from database.checkpoint_store import CheckpointStore
from database.graph_store import EmbeddedGraphStore
from engine.community_detector import detect_code_communities
from engine.fleet_runner import FleetRunner, parse_fleet_csv
from engine.scanner_fusion_engine import (
    _paths_match,
    detect_scanner_format,
    fuse_findings_with_cpg,
    parse_external_scanner_report,
)
from models import (
    Finding,
    FleetRepoSpec,
    FleetRunRequest,
    ScannerFusionResponse,
)

RAW_GITLEAKS_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"
RAW_TRIVY_TOKEN = "AKIAIOSFODNN7EXAMPLE99"


def _init_git_repo(repo_dir: Path) -> str:
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "Alastor Test"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "test@alastor.local"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-m", "init"],
        check=True,
        capture_output=True,
        text=True,
    )
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


class TestScannerFormatDetectionAndParsing:
    def test_sarif_2_1_generic_detection_and_normalization(self, tmp_path: Path):
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        uri_prefix = repo_root.as_uri()
        sarif_payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Bandit",
                            "rules": [
                                {
                                    "id": "B608",
                                    "shortDescription": {"text": "Possible SQL injection vector"},
                                    "properties": {"tags": ["security", "CWE-89"]},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "B608",
                            "level": "warning",
                            "message": {"text": "SQL string built via format()."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f"{uri_prefix}/src/db.py"},
                                        "region": {
                                            "startLine": 19,
                                            "endLine": 19,
                                            "startColumn": 5,
                                            "snippet": {"text": 'cursor.execute("SELECT * FROM t WHERE id=%s" % x)'},
                                        },
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        assert detect_scanner_format(sarif_payload) == "SARIF_2_1"
        fmt, findings = parse_external_scanner_report(
            json.dumps(sarif_payload),
            repo_root=str(repo_root),
        )
        assert fmt == "SARIF_2_1"
        assert len(findings) == 1
        f = findings[0]
        assert f.source_engine == "SARIF"
        assert f.severity == "MEDIUM"
        assert f.cwe_id == "CWE-89"
        assert f.path_nodes[-1]["filepath"] == "src/db.py"
        assert f.path_nodes[-1]["start_line"] == 19
        assert f.best_fix_location is not None
        assert f.best_fix_location.filepath == "src/db.py"

    def test_codeql_sarif_detection_cwe_severity_and_codeflows(self):
        codeql_payload = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [
                                {
                                    "id": "py/command-line-injection",
                                    "name": "Uncontrolled command line",
                                    "shortDescription": {"text": "Command built from user-controlled source"},
                                    "defaultConfiguration": {"level": "error"},
                                    "properties": {
                                        "tags": ["security", "external/cwe/cwe-078"],
                                        "security-severity": "9.8",
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/command-line-injection",
                            "ruleIndex": 0,
                            "level": "error",
                            "message": {"text": "This command line depends on a user-provided value."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "api\\exec.py"},
                                        "region": {
                                            "startLine": 28,
                                            "startColumn": 5,
                                            "snippet": {"text": "os.system(cmd)"},
                                        },
                                    }
                                }
                            ],
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": {
                                                        "physicalLocation": {
                                                            "artifactLocation": {"uri": "api/routes.py"},
                                                            "region": {"startLine": 10, "snippet": {"text": "cmd = req.args['c']"}},
                                                        },
                                                        "message": {"text": "Source"},
                                                    }
                                                },
                                                {
                                                    "location": {
                                                        "physicalLocation": {
                                                            "artifactLocation": {"uri": "api/exec.py"},
                                                            "region": {"startLine": 28, "snippet": {"text": "os.system(cmd)"}},
                                                        },
                                                        "message": {"text": "Sink"},
                                                    }
                                                },
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        assert detect_scanner_format(codeql_payload) == "CODEQL_SARIF"
        fmt, findings = parse_external_scanner_report(json.dumps(codeql_payload))
        assert fmt == "CODEQL_SARIF"
        assert len(findings) == 1
        f = findings[0]
        assert f.source_engine == "CODEQL"
        assert f.severity == "CRITICAL"
        assert f.cvss_score == pytest.approx(9.8)
        assert f.cwe_id == "CWE-78"
        assert len(f.path_nodes) >= 2
        assert f.path_nodes[-1]["filepath"] == "api/exec.py"
        assert f.path_nodes[-1]["start_line"] == 28

    def test_semgrep_json_detection_and_normalization(self):
        semgrep_payload = {
            "version": "1.95.0",
            "results": [
                {
                    "check_id": "python.lang.security.audit.formatted-sql-query",
                    "path": "payments/queries.py",
                    "start": {"line": 14, "col": 5},
                    "end": {"line": 14, "col": 62},
                    "extra": {
                        "message": "Detected possible formatted SQL query.",
                        "severity": "ERROR",
                        "lines": 'cursor.execute(f"SELECT * FROM orders WHERE id={order_id}")',
                        "fix": 'cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))',
                        "metadata": {
                            "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                            "owasp": ["A03:2021 - Injection"],
                        },
                    },
                }
            ],
            "errors": [],
        }
        assert detect_scanner_format(semgrep_payload) == "SEMGREP_JSON"
        fmt, findings = parse_external_scanner_report(json.dumps(semgrep_payload))
        assert fmt == "SEMGREP_JSON"
        assert len(findings) == 1
        f = findings[0]
        assert f.source_engine == "SEMGREP"
        assert f.severity == "HIGH"
        assert f.cwe_id == "CWE-89"
        assert f.path_nodes[-1]["filepath"] == "payments/queries.py"
        assert f.path_nodes[-1]["start_line"] == 14
        assert "A03:2021" in (f.owasp_category or "")

    def test_trivy_json_vulnerabilities_misconfigs_and_secret_scrubbing(self):
        trivy_payload = {
            "SchemaVersion": 2,
            "ArtifactName": ".",
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-32681",
                            "PkgName": "requests",
                            "InstalledVersion": "2.28.1",
                            "FixedVersion": "2.31.0",
                            "Severity": "HIGH",
                            "Title": "Proxy-Authorization header leak",
                            "Description": "Requests leaks Proxy-Authorization header on redirect.",
                            "CweIDs": ["CWE-522"],
                            "CVSS": {"nvd": {"V3Score": 6.1}},
                        }
                    ],
                },
                {
                    "Target": "Dockerfile",
                    "Class": "config",
                    "Type": "dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "Image user should not be 'root'",
                            "Description": "Running containers with root privileges increases blast radius.",
                            "Resolution": "Add USER nonroot directive.",
                            "Severity": "HIGH",
                            "CauseMetadata": {"StartLine": 6, "EndLine": 6},
                        }
                    ],
                },
                {
                    "Target": "deploy/secrets.py",
                    "Class": "secret",
                    "Secrets": [
                        {
                            "RuleID": "aws-access-key-id",
                            "Category": "AWS",
                            "Severity": "CRITICAL",
                            "Title": f"AWS Access Key exposed: {RAW_TRIVY_TOKEN}",
                            "StartLine": 4,
                            "EndLine": 4,
                            "Match": f"AWS_KEY = '{RAW_TRIVY_TOKEN}'",
                            "Code": {
                                "Lines": [
                                    {"Number": 4, "Content": f"AWS_KEY = '{RAW_TRIVY_TOKEN}'"}
                                ]
                            },
                        }
                    ],
                },
            ],
        }
        assert detect_scanner_format(trivy_payload) == "TRIVY_JSON"
        fmt, findings = parse_external_scanner_report(json.dumps(trivy_payload))
        assert fmt == "TRIVY_JSON"
        assert len(findings) == 3

        vuln_f = next(f for f in findings if f.scan_engine == "SCA")
        iac_f = next(f for f in findings if f.scan_engine == "IaC")
        sec_f = next(f for f in findings if f.is_secret_finding)

        assert vuln_f.source_engine == "TRIVY"
        assert vuln_f.cve_id == "CVE-2023-32681"
        assert vuln_f.cwe_id == "CWE-522"
        assert iac_f.source_engine == "TRIVY"
        assert iac_f.path_nodes[-1]["filepath"] == "Dockerfile"
        assert iac_f.path_nodes[-1]["start_line"] == 6
        assert sec_f.source_engine == "TRIVY"
        assert sec_f.cwe_id == "CWE-798"
        assert sec_f.secret_value_raw is None
        for f in findings:
            assert RAW_TRIVY_TOKEN not in f.model_dump_json()

    def test_gitleaks_json_strict_raw_secret_scrubbing_and_empty_handling(self):
        gitleaks_payload = [
            {
                "Description": f"GitHub Personal Access Token ({RAW_GITLEAKS_TOKEN})",
                "StartLine": 3,
                "EndLine": 3,
                "StartColumn": 10,
                "EndColumn": 52,
                "Match": f'GITHUB_TOKEN = "{RAW_GITLEAKS_TOKEN}"',
                "Secret": RAW_GITLEAKS_TOKEN,
                "File": "config/settings.py",
                "Commit": "deadbeef1234",
                "Entropy": 4.5,
                "Author": "dev@example.com",
                "RuleID": "github-pat",
                "Fingerprint": "deadbeef1234:config/settings.py:github-pat:3",
            }
        ]
        assert detect_scanner_format(gitleaks_payload) == "GITLEAKS_JSON"
        fmt, findings = parse_external_scanner_report(json.dumps(gitleaks_payload))
        assert fmt == "GITLEAKS_JSON"
        assert len(findings) == 1
        f = findings[0]
        assert f.source_engine == "GITLEAKS"
        assert f.cwe_id == "CWE-798"
        assert f.is_secret_finding is True
        assert f.secret_value_raw is None
        assert RAW_GITLEAKS_TOKEN not in f.model_dump_json()
        assert RAW_GITLEAKS_TOKEN not in f.title
        assert RAW_GITLEAKS_TOKEN not in f.description
        assert f.best_fix_location is not None
        assert RAW_GITLEAKS_TOKEN not in f.best_fix_location.code_snippet

        fused = fuse_findings_with_cpg(findings, [], project_path=None)
        assert isinstance(fused, ScannerFusionResponse)
        assert RAW_GITLEAKS_TOKEN not in fused.model_dump_json()

        with pytest.raises(ValueError):
            detect_scanner_format([])

        fmt_empty, empty_findings = parse_external_scanner_report("[]", source_format="GITLEAKS_JSON")
        assert fmt_empty == "GITLEAKS_JSON"
        assert empty_findings == []

    def test_checkov_json_single_and_multi_framework_formats(self):
        checkov_payload = [
            {
                "check_type": "terraform",
                "results": {
                    "passed_checks": [],
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_20",
                            "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                            "file_path": "/infra/main.tf",
                            "file_line_range": [12, 18],
                            "resource": "aws_s3_bucket.public_assets",
                            "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-1",
                            "severity": "HIGH",
                            "code_block": [[12, 'resource "aws_s3_bucket" "public_assets" {']],
                        }
                    ],
                },
            },
            {
                "check_type": "dockerfile",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_DOCKER_3",
                            "check_name": "Ensure that a user for the container has been created",
                            "file_path": "/Dockerfile",
                            "file_line_range": [1, 5],
                            "resource": "Dockerfile",
                        }
                    ]
                },
            },
        ]
        assert detect_scanner_format(checkov_payload) == "CHECKOV_JSON"
        fmt, findings = parse_external_scanner_report(json.dumps(checkov_payload))
        assert fmt == "CHECKOV_JSON"
        assert len(findings) == 2
        assert all(f.source_engine == "CHECKOV" for f in findings)
        assert all(f.scan_engine == "IaC" for f in findings)
        assert findings[0].path_nodes[-1]["filepath"] == "infra/main.tf"
        assert findings[0].path_nodes[-1]["start_line"] == 12
        assert findings[0].cwe_id in ("CWE-732", "CWE-16", "CWE-284")
        assert findings[1].path_nodes[-1]["filepath"] == "Dockerfile"

    def test_rejects_malformed_unrecognizable_mismatched_and_traversal_reports(self, tmp_path: Path):
        with pytest.raises(ValueError):
            parse_external_scanner_report("{not valid json")
        with pytest.raises(ValueError):
            detect_scanner_format({"hello": "world"})
        with pytest.raises(ValueError):
            parse_external_scanner_report(
                json.dumps({"results": [], "errors": []}),
                source_format="TRIVY_JSON",
            )

        traversal_semgrep = {
            "results": [
                {
                    "check_id": "python.sqli",
                    "path": "../../etc/passwd",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"message": "bad", "severity": "ERROR", "lines": "root:x:0:0:"},
                }
            ],
            "errors": [],
        }
        with pytest.raises(ValueError):
            parse_external_scanner_report(json.dumps(traversal_semgrep), repo_root=str(tmp_path))

        encoded_traversal_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CustomTool", "rules": []}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "level": "error",
                            "message": {"text": "leak"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file:///repo/%2e%2e/%2e%2e/etc/shadow"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        with pytest.raises(ValueError):
            parse_external_scanner_report(json.dumps(encoded_traversal_sarif), repo_root=str(tmp_path))


class TestScannerFusionWithCPG:
    def test_corroboration_dedup_and_no_native_clobbering(self):
        native_sqli = Finding(
            id="nat-sqli-1",
            rule_id="RULE-7-SQLI-FORMAT",
            severity="HIGH",
            title="Unparameterized SQL String Interpolation in cursor.execute",
            description="Native CPG trace confirmed unparameterized query.",
            cwe_id="CWE-89",
            path_nodes=[
                {
                    "id": "node-nat-1",
                    "label": "Call",
                    "name": "cursor.execute",
                    "code": 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
                    "filepath": "payments/db.py",
                    "start_line": 14,
                    "end_line": 14,
                    "is_sink": True,
                }
            ],
        )
        semgrep_report = {
            "version": "1.90.0",
            "results": [
                {
                    "check_id": "python.lang.security.audit.formatted-sql-query",
                    "path": "payments/db.py",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 15, "col": 50},
                    "extra": {
                        "message": "Formatted SQL query detected.",
                        "severity": "ERROR",
                        "lines": 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
                        "metadata": {"cwe": ["CWE-89"]},
                    },
                }
            ],
            "errors": [],
        }
        fmt, imported = parse_external_scanner_report(json.dumps(semgrep_report))
        resp = fuse_findings_with_cpg(
            imported=imported,
            native_findings=[native_sqli],
            project_path=None,
            detected_format=fmt,
        )
        assert resp.detected_format == "SEMGREP_JSON"
        assert resp.imported_raw_count == 1
        assert resp.normalized_count == 1
        assert resp.corroborated_count == 1
        assert resp.new_unique_count == 0
        assert len(resp.findings) == 1
        merged_nat = resp.findings[0]
        assert merged_nat.id == "nat-sqli-1"
        assert "SEMGREP" in merged_nat.corroborated_by
        assert "Native CPG trace confirmed unparameterized query." in merged_nat.description
        assert "SEMGREP" in merged_nat.description

    def test_unique_finding_cpg_enrichment_and_optional_s6_verify(self, tmp_path: Path):
        repo_dir = tmp_path / "app_repo"
        src_dir = repo_dir / "api"
        src_dir.mkdir(parents=True)
        target_file = src_dir / "orders.py"
        target_file.write_text(
            "import subprocess\n\n"
            "def run_export(user_arg):\n"
            "    cmd = f'export --id={user_arg}'\n"
            "    return subprocess.run(cmd, shell=True)\n",
            encoding="utf-8",
        )

        scanned, _ = scan_directory_with_telemetry(str(repo_dir))
        all_nodes = []
        all_edges = []
        for sf in scanned:
            f_nodes, f_edges = ASTNormalizer(sf).normalize()
            all_nodes.extend(f_nodes)
            all_edges.extend(f_edges)

        store_db = tmp_path / "cpg.db"
        gstore = EmbeddedGraphStore(str(store_db))
        try:
            gstore.ingest_cpg(all_nodes, all_edges)
            comm_map = detect_code_communities(all_nodes, all_edges, None, [], graph_engine_mode="EMBEDDED_SQLITE")
            gstore.save_communities(comm_map)

            codeql_report = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "rules": [
                                    {
                                        "id": "py/command-line-injection",
                                        "properties": {
                                            "tags": ["security", "external/cwe/cwe-078"],
                                            "security-severity": "9.8",
                                        },
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/command-line-injection",
                                "level": "error",
                                "message": {"text": "Shell command depends on user_arg."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "api/orders.py"},
                                            "region": {
                                                "startLine": 5,
                                                "snippet": {"text": "subprocess.run(cmd, shell=True)"},
                                            },
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
            fmt, imported = parse_external_scanner_report(json.dumps(codeql_report), repo_root=str(repo_dir))
            resp = fuse_findings_with_cpg(
                imported=imported,
                native_findings=[],
                graph_store=gstore,
                project_path=str(repo_dir),
                run_s6_verify=True,
                detected_format=fmt,
            )
            assert resp.new_unique_count == 1
            assert resp.corroborated_count == 0
            assert resp.cpg_enriched_count >= 1
            assert resp.s6_verified_count >= 1
            enriched_f = resp.findings[0]
            assert enriched_f.source_engine == "CODEQL"
            assert any("run_export" in str(n) for n in enriched_f.path_nodes) or "run_export" in enriched_f.reachability_reason
            assert comm_map.communities
            assert comm_map.communities[0].label in enriched_f.reachability_reason
        finally:
            gstore.close()

        # Also test resilient fallback when graph_store is a disconnected/failing object
        class _BrokenGraphStore:
            def get_counts(self):
                raise RuntimeError("Neo4j offline")

            def get_communities(self):
                raise RuntimeError("Neo4j offline")

        resp_fb = fuse_findings_with_cpg(
            imported=imported,
            native_findings=[],
            graph_store=_BrokenGraphStore(),
            project_path=str(repo_dir),
            run_s6_verify=False,
        )
        assert resp_fb.new_unique_count == 1
        assert resp_fb.cpg_enriched_count >= 1


class TestFleetCsvAndRunner:
    def test_parse_fleet_csv_valid_and_rejects_unsafe_entries(self):
        csv_text = (
            "# Fleet manifest comment\n"
            "REPO,App_Group,Branch,Fusion_Reports,Profile\n"
            "\n"
            "payments-svc,payments-app,main,reports/semgrep.json;reports/trivy.json,deterministic\n"
            "docs-svc,docs-app,,reports/checkov.json|reports/sarif.json,\n"
        )
        specs = parse_fleet_csv(csv_text)
        assert len(specs) == 2
        assert specs[0] == FleetRepoSpec(
            repo="payments-svc",
            app_group="payments-app",
            branch="main",
            fusion_reports=["reports/semgrep.json", "reports/trivy.json"],
            profile="deterministic",
        )
        assert specs[1] == FleetRepoSpec(
            repo="docs-svc",
            app_group="docs-app",
            branch=None,
            fusion_reports=["reports/checkov.json", "reports/sarif.json"],
            profile="deterministic",
        )

        # Missing repo column
        with pytest.raises(ValueError):
            parse_fleet_csv("app_group,branch\npayments,main\n")

        # Unsafe repo entries & CSV formula injection
        bad_csvs = [
            "repo,app_group\nfile:///etc/passwd,payments\n",
            "repo,app_group\next::sh -c id,payments\n",
            "repo,app_group\n--upload-pack=evil,payments\n",
            "repo,app_group\n../../etc/passwd,payments\n",
            "repo,app_group\npayments-svc,=CMD()\n",
            "repo,app_group,profile\npayments-svc,payments,+evil\n",
            "repo,app_group\n,payments\n",
        ]
        for bad in bad_csvs:
            with pytest.raises(ValueError):
                parse_fleet_csv(bad)

    def test_end_to_end_fleet_runner_group_by_app_and_resume(self, tmp_path: Path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        vault_dir = tmp_path / "vault"

        # Repo 1: vulnerable payments-app
        payments_repo = workspace / "payments-svc"
        payments_repo.mkdir()
        (payments_repo / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        (payments_repo / "app.py").write_text(
            "import sqlite3\n\n"
            "def lookup_account(account_id):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    cursor = conn.cursor()\n"
            '    return cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}").fetchall()\n',
            encoding="utf-8",
        )
        _init_git_repo(payments_repo)

        # Semgrep report matching the SQLi line in payments-svc/app.py
        semgrep_path = payments_repo / "semgrep.json"
        semgrep_path.write_text(
            json.dumps(
                {
                    "version": "1.95.0",
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.formatted-sql-query",
                            "path": "app.py",
                            "start": {"line": 6, "col": 12},
                            "end": {"line": 6, "col": 70},
                            "extra": {
                                "message": "SQL string formatting detected.",
                                "severity": "ERROR",
                                "lines": 'cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}")',
                                "metadata": {"cwe": ["CWE-89"]},
                            },
                        }
                    ],
                    "errors": [],
                }
            ),
            encoding="utf-8",
        )

        # Repo 2: clean docs-app
        docs_repo = workspace / "docs-svc"
        docs_repo.mkdir()
        (docs_repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
        (docs_repo / "docs_helper.py").write_text(
            "def format_heading(title: str) -> str:\n"
            "    return title.strip().title()\n",
            encoding="utf-8",
        )
        _init_git_repo(docs_repo)

        csv_manifest = (
            "repo,app_group,branch,fusion_reports,profile\n"
            f"{payments_repo},payments-app,main,semgrep.json,deterministic\n"
            f"{docs_repo},docs-app,main,,deterministic\n"
        )

        store = CheckpointStore(str(vault_dir))
        try:
            runner = FleetRunner(vault_dir=str(vault_dir), checkpoint_store=store)
            req = FleetRunRequest(
                manifest_name="q4-release-fleet",
                csv_content=csv_manifest,
                group_by_app=True,
                resume=True,
                max_workers=2,
            )
            resp = runner.run_fleet(req)

            assert resp.status == "COMPLETED"
            assert resp.total_repos == 2
            assert resp.completed_repos == 2
            assert resp.failed_repos == 0

            res_by_group = {r.app_group: r for r in resp.repo_results}
            assert res_by_group["payments-app"].corroborated_count >= 1
            assert res_by_group["payments-app"].go_live_decision == "NO_GO_HOLD_RELEASE"
            assert res_by_group["docs-app"].go_live_decision == "GO_LIVE_APPROVED"

            rollups_by_group = {g.app_group: g for g in resp.app_rollups}
            assert rollups_by_group["payments-app"].go_live_decision == "NO_GO_HOLD_RELEASE"
            assert rollups_by_group["docs-app"].go_live_decision == "GO_LIVE_APPROVED"

            persisted = store.list_fleet_runs()
            assert persisted.total == 1
            assert persisted.runs[0].fleet_run_id == resp.fleet_run_id

            # Second run with resume=True must reuse SQLite stage checkpoints
            resp_resume = runner.run_fleet(req)
            assert resp_resume.status == "COMPLETED"
            for rr in resp_resume.repo_results:
                assert rr.status == "RESUMED_COMPLETED"
                assert "S0_CPG" in rr.resumed_stages
                assert "S1_RULES" in rr.resumed_stages
        finally:
            store.close()

    def test_fleet_runner_stop_after_and_resume_continuation(self, tmp_path: Path):
        repo = tmp_path / "svc"
        repo.mkdir()
        (repo / "app.py").write_text("def ok(x):\n    return x + 1\n", encoding="utf-8")
        _init_git_repo(repo)

        vault_dir = tmp_path / "vault"
        store = CheckpointStore(str(vault_dir))
        try:
            runner = FleetRunner(vault_dir=str(vault_dir), checkpoint_store=store)
            spec = FleetRepoSpec(repo=str(repo), app_group="core-app")

            partial_res, _ = runner.run_single_repo(spec, resume=True, stop_after="s1")
            assert partial_res.status == "COMPLETED"
            run_rec = store.get_run(partial_res.run_id)
            assert run_rec is not None
            assert run_rec.status == "PARTIAL"
            stage_names = [s.stage_name for s in run_rec.stages]
            assert "S0_CPG" in stage_names
            assert "S1_RULES" in stage_names
            assert "S9_REPORTS" not in stage_names

            resumed_res, _ = runner.run_single_repo(spec, resume=True, stop_after=None)
            assert resumed_res.run_id == partial_res.run_id
            assert resumed_res.status == "RESUMED_COMPLETED"
            assert "S0_CPG" in resumed_res.resumed_stages
            assert "S1_RULES" in resumed_res.resumed_stages
            full_rec = store.get_run(resumed_res.run_id)
            assert full_rec is not None
            assert full_rec.status == "COMPLETED"
            assert any(s.stage_name == "S9_REPORTS" for s in full_rec.stages)
        finally:
            store.close()

    def test_fleet_runner_per_repo_failure_isolation_and_hostile_guard(self, tmp_path: Path):
        workspace = tmp_path / "allowed_ws"
        workspace.mkdir()
        valid_repo = workspace / "good-repo"
        valid_repo.mkdir()
        (valid_repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
        (valid_repo / "app.py").write_text("def ok():\n    return 42\n", encoding="utf-8")

        outside_repo = tmp_path / "outside_secret_repo"
        outside_repo.mkdir()
        (outside_repo / "app.py").write_text("def x():\n    return 1\n", encoding="utf-8")

        def _confine(raw: str) -> str:
            real_ws = workspace.resolve()
            cand = Path(raw)
            if not cand.is_absolute():
                cand = (real_ws / raw)
            real_cand = cand.resolve()
            if real_ws not in real_cand.parents and real_cand != real_ws:
                raise ValueError(f"Path outside workspace: {raw}")
            return str(real_cand)

        vault_dir = tmp_path / "vault"
        store = CheckpointStore(str(vault_dir))
        try:
            runner = FleetRunner(
                vault_dir=str(vault_dir),
                checkpoint_store=store,
                workspace_confinement_fn=_confine,
            )
            req = FleetRunRequest(
                manifest_name="isolation-test",
                repos=[
                    FleetRepoSpec(repo=str(valid_repo), app_group="good-group"),
                    FleetRepoSpec(repo=str(outside_repo), app_group="bad-group"),
                    FleetRepoSpec(repo="https://github.com/example/offline-remote.git", app_group="remote-group"),
                ],
                group_by_app=True,
                resume=False,
                max_workers=2,
            )
            real_popen = subprocess.Popen
            popen_argvs = []

            def _spy_popen(args, *pargs, **kwargs):
                popen_argvs.append(list(args) if isinstance(args, (list, tuple)) else [str(args)])
                return real_popen(args, *pargs, **kwargs)

            with mock.patch("subprocess.Popen", side_effect=_spy_popen):
                resp = runner.run_fleet(req)

            assert not any("clone" in argv for argv in popen_argvs)
            assert resp.status == "PARTIAL"
            assert resp.total_repos == 3
            assert resp.completed_repos == 1
            assert resp.failed_repos == 2

            rollups = {r.app_group: r for r in resp.app_rollups}
            assert rollups["good-group"].go_live_decision == "GO_LIVE_APPROVED"
            assert rollups["bad-group"].go_live_decision == "NO_GO_HOLD_RELEASE"
            assert rollups["remote-group"].go_live_decision == "NO_GO_HOLD_RELEASE"
        finally:
            store.close()

    def test_fleet_runner_hostile_git_and_no_raw_secret_in_checkpoints(self, tmp_path: Path):
        workspace = tmp_path / "ws"
        workspace.mkdir()
        vault_dir = tmp_path / "vault"

        # Repo A: hostile core.fsmonitor + working-tree secret token (neutralized, scanned safely, raw secret scrubbed)
        repo_a = workspace / "repo-a"
        repo_a.mkdir()
        pwn_marker = tmp_path / "fsmonitor_pwned.txt"
        (repo_a / "cfg.py").write_text(f'GITHUB_TOKEN = "{RAW_GITLEAKS_TOKEN}"\n', encoding="utf-8")
        _init_git_repo(repo_a)
        subprocess.run(
            ["git", "-C", str(repo_a), "config", "core.fsmonitor", f"python -c \"open(r'{pwn_marker}', 'w').write('1')\""],
            check=True,
            capture_output=True,
            text=True,
        )

        # Repo B: hostile url.*.insteadOf -> fails closed cleanly without breaking Repo A
        repo_b = workspace / "repo-b"
        repo_b.mkdir()
        (repo_b / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
        _init_git_repo(repo_b)
        subprocess.run(
            ["git", "-C", str(repo_b), "config", "url.https://evil.invalid/.insteadOf", "https://github.com/"],
            check=True,
            capture_output=True,
            text=True,
        )

        store = CheckpointStore(str(vault_dir))
        try:
            runner = FleetRunner(vault_dir=str(vault_dir), checkpoint_store=store)
            req = FleetRunRequest(
                manifest_name="hostile-safety",
                repos=[
                    FleetRepoSpec(repo=str(repo_a), app_group="grp-a"),
                    FleetRepoSpec(repo=str(repo_b), app_group="grp-b"),
                ],
                group_by_app=True,
                resume=False,
                max_workers=1,
            )
            resp = runner.run_fleet(req)
            assert not pwn_marker.exists()
            assert resp.status == "PARTIAL"
            assert resp.completed_repos == 1
            assert resp.failed_repos == 1

            by_grp = {r.app_group: r for r in resp.repo_results}
            assert by_grp["grp-a"].status == "COMPLETED"
            assert by_grp["grp-a"].total_findings >= 1
            assert by_grp["grp-b"].status == "FAILED"
            assert "insteadOf" in (by_grp["grp-b"].error or "")
        finally:
            store.close()

        for suffix in ("", "-wal", "-shm"):
            db_part = vault_dir / f"checkpoints.db{suffix}"
            if db_part.exists():
                db_bytes = db_part.read_text(encoding="utf-8", errors="ignore")
                assert RAW_GITLEAKS_TOKEN not in db_bytes


class TestTask2ReviewRegressionFixes:
    def test_secret_cpg_enrichment_never_leaks_raw_secret_into_path_nodes(self, tmp_path: Path):
        repo_dir = tmp_path / "sec_repo"
        repo_dir.mkdir()
        custom_secret = "custom_nonregex_secret_token_987654321"
        cfg_file = repo_dir / "config.py"
        cfg_file.write_text(
            "def load_credentials():\n"
            f'    gh = "{RAW_GITLEAKS_TOKEN}"\n'
            "    return gh\n"
            "\n"
            "def load_custom_secret():\n"
            f'    custom = "{custom_secret}"\n'
            "    return custom\n",
            encoding="utf-8",
        )
        scanned, _ = scan_directory_with_telemetry(str(repo_dir))
        nodes, edges = [], []
        for sf in scanned:
            fn_nodes, fn_edges = ASTNormalizer(sf).normalize()
            nodes.extend(fn_nodes)
            edges.extend(fn_edges)
        gstore = EmbeddedGraphStore(str(tmp_path / "cpg_sec.db"))
        try:
            gstore.ingest_cpg(nodes, edges)
            comm_map = detect_code_communities(nodes, edges, None, [], graph_engine_mode="EMBEDDED_SQLITE")
            gstore.save_communities(comm_map)

            gitleaks_report = [
                {
                    "Description": "GitHub PAT",
                    "StartLine": 2,
                    "EndLine": 2,
                    "Match": f'gh = "{RAW_GITLEAKS_TOKEN}"',
                    "Secret": RAW_GITLEAKS_TOKEN,
                    "File": "config.py",
                    "RuleID": "github-pat",
                }
            ]
            fmt, imported = parse_external_scanner_report(json.dumps(gitleaks_report), repo_root=str(repo_dir))
            direct_custom = Finding(
                id="sec-direct-1",
                rule_id="EXT-GITLEAKS-custom",
                severity="HIGH",
                title="Hardcoded custom secret",
                description=f"Found {custom_secret}",
                cwe_id="CWE-798",
                is_secret_finding=True,
                secret_value_raw=custom_secret,
                path_nodes=[
                    {
                        "id": "n-custom",
                        "label": "Assignment",
                        "filepath": "config.py",
                        "start_line": 6,
                        "code": custom_secret,
                        "is_sink": True,
                    }
                ],
                source_engine="GITLEAKS",
            )
            resp = fuse_findings_with_cpg(
                imported=imported + [direct_custom],
                native_findings=[],
                graph_store=gstore,
                project_path=str(repo_dir),
                run_s6_verify=True,
                detected_format=fmt,
                correlate_cpg=True,
            )
            assert resp.cpg_enriched_count == 2
            dumped = resp.model_dump_json()
            assert RAW_GITLEAKS_TOKEN not in dumped
            assert custom_secret not in dumped
            for f in resp.findings:
                assert f.secret_value_raw is None
                assert any(n.get("label") == "Function" for n in f.path_nodes)
                for n in f.path_nodes:
                    assert RAW_GITLEAKS_TOKEN not in str(n)
                    assert custom_secret not in str(n)
        finally:
            gstore.close()

    def test_fleet_runner_confines_fusion_reports_strictly_inside_repo(self, tmp_path: Path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        repo = ws / "app-repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
        (repo / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

        sibling_report = ws / "sibling_report.json"
        sibling_report.write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")
        outside_report = tmp_path / "outside_report.json"
        outside_report.write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")

        # Also create an escaping directory link inside repo (NTFS junction on Windows / symlink on POSIX)
        escaped_dir = tmp_path / "escaped_reports_dir"
        escaped_dir.mkdir()
        (escaped_dir / "escaped.json").write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")
        link_dir = repo / "linked_reports"
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link_dir), str(escaped_dir)], check=True, capture_output=True)
        else:
            os.symlink(str(escaped_dir), str(link_dir), target_is_directory=True)

        def _confine(raw: str) -> str:
            real_ws = ws.resolve()
            cand = Path(raw) if Path(raw).is_absolute() else (real_ws / raw)
            real_cand = cand.resolve()
            if real_ws not in real_cand.parents and real_cand != real_ws:
                raise ValueError(f"Outside workspace: {raw}")
            return str(real_cand)

        vault = tmp_path / "vault"
        store = CheckpointStore(str(vault))
        try:
            for conf_fn in (None, _confine):
                runner = FleetRunner(vault_dir=str(vault), checkpoint_store=store, workspace_confinement_fn=conf_fn)
                for bad_rp in (
                    str(sibling_report),
                    "sibling_report.json",
                    str(outside_report),
                    "linked_reports/escaped.json",
                    "D:\\cross_drive\\evil.json" if os.name == "nt" else "/etc/passwd",
                ):
                    res, _ = runner.run_single_repo(
                        FleetRepoSpec(repo=str(repo), app_group="g1", fusion_reports=[bad_rp]),
                        resume=False,
                    )
                    assert res.status == "FAILED"
                    assert res.go_live_decision == "NO_GO_HOLD_RELEASE"
                    assert res.error
        finally:
            if link_dir.exists():
                if os.name == "nt":
                    os.rmdir(link_dir)
                else:
                    os.unlink(link_dir)
            store.close()

    def test_fleet_runner_concurrent_workers_isolated_and_no_live_osv_egress(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        specs = []
        for idx in range(4):
            rdir = ws / f"svc-{idx}"
            rdir.mkdir()
            (rdir / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            (rdir / "package-lock.json").write_text(
                json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.21"}}}),
                encoding="utf-8",
            )
            (rdir / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
            specs.append(FleetRepoSpec(repo=str(rdir), app_group=f"grp-{idx}"))

        vault = tmp_path / "vault"
        store = CheckpointStore(str(vault))
        try:
            runner = FleetRunner(vault_dir=str(vault), checkpoint_store=store)
            with mock.patch("requests.post", side_effect=AssertionError("Unexpected live OSV HTTP egress")):
                resp = runner.run_fleet(
                    FleetRunRequest(
                        manifest_name="concurrent-offline",
                        repos=specs,
                        group_by_app=True,
                        resume=False,
                        max_workers=4,
                    )
                )
            assert resp.status == "COMPLETED"
            assert resp.completed_repos == 4
            assert resp.failed_repos == 0
            assert not (vault / "osv_advisory_cache.json").exists()
            assert not (vault / ".alastor_vault").exists()
        finally:
            store.close()

    def test_stop_after_halts_before_full_gate_fails_closed_no_go(self, tmp_path: Path):
        repo = tmp_path / "clean_svc"
        repo.mkdir()
        (repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
        (repo / "app.py").write_text("def ok():\n    return 42\n", encoding="utf-8")

        vault = tmp_path / "vault"
        store = CheckpointStore(str(vault))
        try:
            runner = FleetRunner(vault_dir=str(vault), checkpoint_store=store)
            res_s0, _ = runner.run_single_repo(FleetRepoSpec(repo=str(repo), app_group="clean-grp"), resume=False, stop_after="s0")
            assert res_s0.go_live_decision == "NO_GO_HOLD_RELEASE"

            res_s1, _ = runner.run_single_repo(FleetRepoSpec(repo=str(repo), app_group="clean-grp"), resume=False, stop_after="s1")
            assert res_s1.go_live_decision == "NO_GO_HOLD_RELEASE"

            fleet_partial = runner.run_fleet(
                FleetRunRequest(
                    manifest_name="partial-stop",
                    repos=[FleetRepoSpec(repo=str(repo), app_group="clean-grp")],
                    group_by_app=True,
                    resume=False,
                    stop_after="s1",
                )
            )
            assert fleet_partial.app_rollups[0].go_live_decision == "NO_GO_HOLD_RELEASE"
        finally:
            store.close()

    def test_resume_invalidates_when_profile_or_fusion_reports_change(self, tmp_path: Path):
        repo = tmp_path / "svc"
        repo.mkdir()
        (repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
        (repo / "app.py").write_text(
            "def f(x):\n"
            "    return x\n",
            encoding="utf-8",
        )
        _init_git_repo(repo)
        semgrep_file = repo / "semgrep.json"

        vault = tmp_path / "vault"
        store = CheckpointStore(str(vault))
        try:
            runner = FleetRunner(vault_dir=str(vault), checkpoint_store=store)

            # Run 1: no fusion reports, deterministic profile
            r1, _ = runner.run_single_repo(FleetRepoSpec(repo=str(repo), app_group="g", profile="deterministic"), resume=True)
            assert r1.status == "COMPLETED"
            assert r1.total_findings == 0

            # Run 2: add semgrep.json -> S0..S2 resume, S3..S9 re-run!
            semgrep_file.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.sqli",
                                "path": "app.py",
                                "start": {"line": 2, "col": 5},
                                "end": {"line": 2, "col": 12},
                                "extra": {"message": "SQLi", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
                            }
                        ],
                        "errors": [],
                    }
                ),
                encoding="utf-8",
            )
            r2, f2 = runner.run_single_repo(
                FleetRepoSpec(repo=str(repo), app_group="g", fusion_reports=["semgrep.json"], profile="deterministic"),
                resume=True,
            )
            assert r2.run_id == r1.run_id
            assert r2.status == "RESUMED_COMPLETED"
            assert {"S0_CPG", "S1_RULES", "S2_SECRETS_SCA"}.issubset(set(r2.resumed_stages))
            assert "S3_FUSION" not in r2.resumed_stages
            assert "S6_VERIFY" not in r2.resumed_stages
            assert r2.total_findings == 1
            assert any("[S6 " in (f.reachability_reason or "") for f in f2)

            # Run 3: edit semgrep.json content -> S3..S9 re-run again!
            semgrep_file.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.sqli",
                                "path": "app.py",
                                "start": {"line": 2, "col": 5},
                                "end": {"line": 2, "col": 12},
                                "extra": {"message": "SQLi updated", "severity": "CRITICAL", "metadata": {"cwe": ["CWE-89"]}},
                            }
                        ],
                        "errors": [],
                    }
                ),
                encoding="utf-8",
            )
            r3, _ = runner.run_single_repo(
                FleetRepoSpec(repo=str(repo), app_group="g", fusion_reports=["semgrep.json"], profile="deterministic"),
                resume=True,
            )
            assert r3.run_id == r1.run_id
            assert "S2_SECRETS_SCA" in r3.resumed_stages
            assert "S3_FUSION" not in r3.resumed_stages
            assert r3.critical_count == 1

            # Run 4: change profile -> S0 resumes, S1..S9 invalidate and re-run!
            r4, _ = runner.run_single_repo(
                FleetRepoSpec(repo=str(repo), app_group="g", fusion_reports=["semgrep.json"], profile="fast-ci"),
                resume=True,
            )
            assert r4.run_id == r1.run_id
            assert "S0_CPG" in r4.resumed_stages
            assert "S1_RULES" not in r4.resumed_stages
            assert "S3_FUSION" not in r4.resumed_stages
        finally:
            store.close()

    def test_posix_abs_paths_rejected_and_dotfiles_preserved_in_paths_match(self, tmp_path: Path):
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        sarif_abs = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Custom", "rules": []}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "level": "error",
                            "message": {"text": "leak"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///etc/passwd"}, "region": {"startLine": 1}}}],
                        }
                    ],
                }
            ],
        }
        with pytest.raises(ValueError):
            parse_external_scanner_report(json.dumps(sarif_abs), repo_root=str(repo_root))

        semgrep_abs = {
            "results": [
                {
                    "check_id": "rule.1",
                    "path": "/etc/passwd",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"message": "bad", "severity": "ERROR"},
                }
            ],
            "errors": [],
        }
        with pytest.raises(ValueError):
            parse_external_scanner_report(json.dumps(semgrep_abs), repo_root=str(repo_root))

        checkov_ok = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "Public ACL",
                        "file_path": "/infra/main.tf",
                        "file_line_range": [1, 3],
                    }
                ]
            },
        }
        _, ck_findings = parse_external_scanner_report(json.dumps(checkov_ok), repo_root=str(repo_root))
        assert ck_findings[0].path_nodes[-1]["filepath"] == "infra/main.tf"

        assert _paths_match(".github/workflows/ci.yml", "./.github/workflows/ci.yml") is True
        assert _paths_match(".env", "env") is False

    def test_same_engine_dedup_does_not_inflate_corroborated_count_and_fleet_attaches_s6(self, tmp_path: Path):
        semgrep_dup = {
            "results": [
                {
                    "check_id": "python.sqli.a",
                    "path": "app.py",
                    "start": {"line": 14, "col": 5},
                    "end": {"line": 14, "col": 40},
                    "extra": {"message": "SQLi A", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
                },
                {
                    "check_id": "python.sqli.b",
                    "path": "app.py",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 15, "col": 40},
                    "extra": {"message": "SQLi B", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
                },
            ],
            "errors": [],
        }
        fmt, imp = parse_external_scanner_report(json.dumps(semgrep_dup))
        resp = fuse_findings_with_cpg(imported=imp, native_findings=[], detected_format=fmt)
        assert len(resp.findings) == 1
        assert resp.new_unique_count == 1
        assert resp.corroborated_count == 0
        assert resp.findings[0].corroborated_by == []
        assert "[Corroborated by" not in resp.findings[0].description

        # Fleet S6 verdicts attached both on fresh run and on --resume
        repo = tmp_path / "vuln_svc"
        repo.mkdir()
        (repo / "requirements.txt").write_text("mkdocs==1.6.0\n", encoding="utf-8")
        (repo / "app.py").write_text(
            "import sqlite3\n"
            "def q(uid):\n"
            "    cur = sqlite3.connect(':memory:').cursor()\n"
            '    return cur.execute(f"SELECT * FROM u WHERE id = {uid}").fetchall()\n',
            encoding="utf-8",
        )
        _init_git_repo(repo)
        vault = tmp_path / "vault"
        store = CheckpointStore(str(vault))
        try:
            runner = FleetRunner(vault_dir=str(vault), checkpoint_store=store)
            spec = FleetRepoSpec(repo=str(repo), app_group="g")
            _, fresh_findings = runner.run_single_repo(spec, resume=True)
            assert fresh_findings
            assert any("[S6 " in (f.reachability_reason or "") for f in fresh_findings)

            res_resumed, resumed_findings = runner.run_single_repo(spec, resume=True)
            assert res_resumed.status == "RESUMED_COMPLETED"
            assert any("[S6 " in (f.reachability_reason or "") for f in resumed_findings)
        finally:
            store.close()


class TestPillar4FinalReviewFusionAndFleetFixes:
    def test_embedded_sqlite_mode_never_attempts_neo4j_bolt_lookup(self, tmp_path: Path):
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("def fn(x):\n    return x\n", encoding="utf-8")

        class _EmbeddedStoreWithNeo4jAttr:
            mode = "EMBEDDED_SQLITE"

            class _FakeClient:
                class _FakeDriver:
                    def session(self):
                        raise AssertionError("Neo4j Bolt session() MUST NOT be called in EMBEDDED_SQLITE mode!")

                driver = _FakeDriver()

            neo4j_client = _FakeClient()

            def __init__(self):
                self._embedded_store = EmbeddedGraphStore(str(tmp_path / "emb.db"))

            def get_communities(self):
                return self._embedded_store.get_communities()

        fake_mgr = _EmbeddedStoreWithNeo4jAttr()
        try:
            semgrep_payload = {
                "results": [
                    {
                        "check_id": "python.sqli",
                        "path": "app.py",
                        "start": {"line": 2, "col": 5},
                        "end": {"line": 2, "col": 12},
                        "extra": {"message": "SQLi", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
                    }
                ],
                "errors": [],
            }
            fmt, imported = parse_external_scanner_report(json.dumps(semgrep_payload), repo_root=str(repo_dir))
            resp = fuse_findings_with_cpg(
                imported=imported,
                native_findings=[],
                graph_store=fake_mgr,
                project_path=str(repo_dir),
                detected_format=fmt,
            )
            assert resp.warnings == []
            assert resp.cpg_enriched_count == 1
        finally:
            fake_mgr._embedded_store.close()

    def test_malformed_line_columns_and_checkov_double_slash_os_prefix_rejected(self, tmp_path: Path):
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        malformed_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Custom", "rules": []}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "level": "warning",
                            "message": {"text": "test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": "bad-int", "endLine": None, "startColumn": "nan"},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        _, sarif_f = parse_external_scanner_report(json.dumps(malformed_sarif), repo_root=str(repo_dir))
        assert len(sarif_f) == 1
        assert sarif_f[0].best_fix_location is not None and sarif_f[0].best_fix_location.line == 1

        checkov_double_slash = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_1",
                        "check_name": "Evil double slash",
                        "file_path": "//etc/passwd",
                        "file_line_range": ["not-an-int", "also-bad"],
                    }
                ]
            },
        }
        with pytest.raises(ValueError):
            parse_external_scanner_report(json.dumps(checkov_double_slash), repo_root=str(repo_dir))

        checkov_bad_lines_ok_path = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_2",
                        "check_name": "Valid path bad line",
                        "file_path": "/infra/main.tf",
                        "file_line_range": ["oops", True],
                    }
                ]
            },
        }
        _, ck_f = parse_external_scanner_report(json.dumps(checkov_bad_lines_ok_path), repo_root=str(repo_dir))
        assert ck_f[0].path_nodes[-1]["start_line"] == 1

    def test_fleet_runner_persists_profile_and_fusion_reports_in_options(self, tmp_path: Path):
        repo = tmp_path / "svc"
        repo.mkdir()
        (repo / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
        (repo / "semgrep.json").write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")
        _init_git_repo(repo)

        vault = tmp_path / "vault"
        store = CheckpointStore(str(vault))
        try:
            runner = FleetRunner(vault_dir=str(vault), checkpoint_store=store)
            res, _ = runner.run_single_repo(
                FleetRepoSpec(
                    repo=str(repo),
                    app_group="payments",
                    profile="fast-ci",
                    fusion_reports=["semgrep.json"],
                ),
                resume=False,
                stop_after="s1",
            )
            saved = store.get_run(res.run_id)
            assert saved is not None
            assert saved.options.get("profile") == "fast-ci"
            assert saved.options.get("fusion_reports") == ["semgrep.json"]
        finally:
            store.close()
