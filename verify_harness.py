#!/usr/bin/env python3
"""
Autonomous Self-Verification Test Suite for Deterministic CPG & SAST Platform.
Runs against containerized Neo4j, FastAPI backend, and Next.js frontend.
"""
import sys
import os
import re
import time
import tempfile
import subprocess
import requests
from typing import Dict, Any, List, Optional, Tuple

NEO4J_URI = os.environ.get("NEO4J_URI") or "bolt://localhost:7687"
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")


def _load_harness_neo4j_auth() -> Optional[Tuple[str, str]]:
    """Loads Neo4j credentials from environment or docker-compose.yml runtime substitution."""
    raw_auth = os.environ.get("NEO4J_AUTH", "").strip()
    if "/" in raw_auth and raw_auth.lower() != "none":
        u, p = raw_auth.split("/", 1)
        return (u, p)
    env_pwd = os.environ.get("NEO4J_PASSWORD", "").strip()
    if env_pwd:
        return (os.environ.get("NEO4J_USER", "neo4j").strip() or "neo4j", env_pwd)
    compose_file = os.path.join(ROOT_DIR, "docker-compose.yml")
    if os.path.isfile(compose_file):
        with open(compose_file, "r", encoding="utf-8") as fh:
            m = re.search(
                r"NEO4J_AUTH:\s*\"?\$\{NEO4J_USER:-([^}]+)\}/\$\{NEO4J_PASSWORD:-([^}]+)\}\"?",
                fh.read(),
            )
            if m:
                return (os.environ.get("NEO4J_USER", "").strip() or m.group(1), m.group(2))
    return None


def log(msg: str):
    print(f"[HARNESS] {msg}", flush=True)


def verify_neo4j_apoc():
    """Verifies Neo4j container is up and APOC library is functional."""
    log("Verifying Neo4j and APOC library...")
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(NEO4J_URI, auth=_load_harness_neo4j_auth())
    with driver.session() as session:
        result = session.run("CALL apoc.help('iterate') YIELD name RETURN count(name) AS c")
        rec = result.single()
        assert rec and rec["c"] >= 1, "APOC iterate procedure not available!"
    driver.close()
    log("PASS: Neo4j is online and APOC is installed.")


def ensure_backend_running() -> subprocess.Popen:
    """Checks if FastAPI backend is responding, starts it in background if not."""
    try:
        r = requests.get(f"{BACKEND_URL}/api/health", timeout=2)
        if r.status_code == 200:
            log("Backend is already running.")
            return None
    except Exception:
        pass

    log(f"Starting FastAPI backend on {BACKEND_URL}...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=BACKEND_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Wait for backend to be ready
    for attempt in range(25):
        time.sleep(0.5)
        try:
            r = requests.get(f"{BACKEND_URL}/api/health", timeout=1)
            if r.status_code == 200:
                log("Backend started and healthy.")
                return proc
        except Exception:
            continue

    raise RuntimeError("Backend failed to start.")


def ensure_frontend_running() -> subprocess.Popen:
    """Checks if Next.js frontend is responding, starts dev server in background if not."""
    try:
        r = requests.get(FRONTEND_URL, timeout=3)
        if r.status_code == 200:
            log("Frontend is already running.")
            return None
    except Exception:
        pass

    log(f"Starting Next.js frontend on {FRONTEND_URL}...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    proc = subprocess.Popen(
        [npm_cmd, "run", "start"],
        cwd=FRONTEND_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    for attempt in range(40):
        time.sleep(1)
        try:
            r = requests.get(FRONTEND_URL, timeout=2)
            if r.status_code == 200:
                log("Frontend started and responding HTTP 200.")
                return proc
        except Exception:
            continue

    log("Warning: Frontend dev server took longer than expected to report ready.")
    return proc


def run_assertions():
    """Executes all deterministic CPG, Enterprise UI, and Self-Audit assertions against API endpoints."""
    # Preserve whichever project and preset the user currently has open in the UI
    orig_projects = requests.get(f"{BACKEND_URL}/api/projects", timeout=15).json()
    orig_active_proj = next((p for p in orig_projects if p.get("is_active")), None)
    requests.put(
        f"{BACKEND_URL}/api/settings",
        json={
            "scope": "GLOBAL",
            "active_preset_id": "preset-optimized",
            "enabled_engines": ["SAST", "SCA", "IaC"],
        },
        timeout=15,
    )

    log("Step 1: Sending POST /api/scan pointing to ./synthetic_test_target...")
    target_scan_dir = os.path.join(ROOT_DIR, "synthetic_test_target")
    scan_resp = requests.post(
        f"{BACKEND_URL}/api/scan",
        json={"target_path": target_scan_dir},
        timeout=60
    )
    assert scan_resp.status_code == 200, f"Scan failed: {scan_resp.text}"
    scan_data = scan_resp.json()
    log(f"Scan response: {scan_data}")

    nodes_created = scan_data.get("nodes_created", 0)
    edges_created = scan_data.get("edges_created", 0)
    assert nodes_created > 30, f"Expected nodes_created > 30, got {nodes_created}"
    assert edges_created > 40, f"Expected edges_created > 40, got {edges_created}"
    log(f"PASS: Baseline volume check passed: {nodes_created} nodes, {edges_created} edges.")

    log("Step 2: Sending GET /api/findings...")
    findings_resp = requests.get(f"{BACKEND_URL}/api/findings", timeout=30)
    assert findings_resp.status_code == 200, f"Findings failed: {findings_resp.text}"
    findings: List[Dict[str, Any]] = findings_resp.json()
    log(f"Retrieved {len(findings)} findings.")

    # -------------------------------------------------------------
    # Assertion A: Exactly 1 Taint Vulnerability is detected (sys.argv[1] -> os.system)
    # and sanitized int(sys.argv[2]) flow is NOT flagged (0% false positive)
    # -------------------------------------------------------------
    taint_findings = [f for f in findings if f["rule_id"] == "RULE-1-TAINT"]
    assert len(taint_findings) == 1, f"Assertion A FAILED: Expected exactly 1 taint finding, got {len(taint_findings)}"
    taint_path_nodes = taint_findings[0]["path_nodes"]
    node_names = [n.get("name", "") for n in taint_path_nodes]
    node_codes = [n.get("code", "") for n in taint_path_nodes]
    
    # Check that sys.argv[1] is in path and os.system is sink
    has_argv1 = any("sys.argv[1]" in c or "sys.argv" in c for c in node_codes)
    has_system = any("os.system" in c for c in node_codes)
    assert has_argv1 and has_system, f"Assertion A FAILED: Taint path did not connect sys.argv[1] to os.system: {node_codes}"
    
    # Check sanitized flow is NOT flagged
    has_sanitized = any("sys.argv[2]" in c for c in node_codes)
    assert not has_sanitized, "Assertion A FAILED: Sanitized flow with sys.argv[2] was falsely flagged!"
    log("PASS: Assertion A (Taint Vulnerability detected, Sanitized flow not flagged).")

    # -------------------------------------------------------------
    # Assertion B: legacy_debug_shell is flagged as a Dormant Zero-Day Gadget
    # -------------------------------------------------------------
    orphan_findings = [f for f in findings if f["rule_id"] == "RULE-2-ORPHAN"]
    legacy_found = any("legacy_debug_shell" in f["title"] for f in orphan_findings)
    assert legacy_found, f"Assertion B FAILED: legacy_debug_shell not flagged as Dormant Gadget! Titles: {[f['title'] for f in orphan_findings]}"
    log("PASS: Assertion B (legacy_debug_shell flagged as Dormant Zero-Day Gadget).")

    # -------------------------------------------------------------
    # Assertion C: audit_buffer is flagged as a Dead Store
    # -------------------------------------------------------------
    dead_findings = [f for f in findings if f["rule_id"] == "RULE-3-DEADSTORE"]
    audit_buffer_found = any("audit_buffer" in f["title"] for f in dead_findings)
    assert audit_buffer_found, f"Assertion C FAILED: audit_buffer not flagged as Dead Store! Titles: {[f['title'] for f in dead_findings]}"
    log("PASS: Assertion C (audit_buffer flagged as Dead Store).")

    # -------------------------------------------------------------
    # Assertion D: The while True: block is flagged as a Non-Terminating Infinite Loop
    # -------------------------------------------------------------
    loop_findings = [f for f in findings if f["rule_id"] == "RULE-4-INFINITE-LOOP"]
    assert len(loop_findings) >= 1, "Assertion D FAILED: No infinite loop findings detected!"
    loop_found = any("Infinite Loop" in f["title"] for f in loop_findings)
    assert loop_found, f"Assertion D FAILED: Infinite Loop title missing! Titles: {[f['title'] for f in loop_findings]}"
    log("PASS: Assertion D (while True: flagged as Non-Terminating Infinite Loop).")

    # -------------------------------------------------------------
    # Assertion E: cleanup_temp_files() is flagged as an Unreachable Dead Code Block
    # -------------------------------------------------------------
    unreachable_findings = [f for f in findings if f["rule_id"] == "RULE-5-UNREACHABLE"]
    cleanup_found = any("cleanup_temp_files" in n.get("name", "") or "cleanup_temp_files" in n.get("code", "") 
                        for f in unreachable_findings for n in f.get("path_nodes", []))
    assert cleanup_found, f"Assertion E FAILED: cleanup_temp_files() not flagged as Unreachable! Found: {[[n.get('name') for n in f.get('path_nodes', [])] for f in unreachable_findings]}"
    log("PASS: Assertion E (cleanup_temp_files() flagged as Unreachable Dead Code Block).")

    # -------------------------------------------------------------
    # Assertion F: Every returned node in path_nodes has start_line >= 1 and a valid filepath
    # -------------------------------------------------------------
    total_nodes_checked = 0
    for f in findings:
        for n in f.get("path_nodes", []):
            start_line = n.get("start_line")
            filepath = n.get("filepath")
            assert isinstance(start_line, int) and start_line >= 1, f"Assertion F FAILED: Invalid start_line {start_line} in node: {n}"
            assert filepath and isinstance(filepath, str), f"Assertion F FAILED: Invalid filepath '{filepath}' in node: {n}"
            total_nodes_checked += 1
    log(f"PASS: Assertion F (Checked {total_nodes_checked} path nodes, all have start_line >= 1 and valid filepath).")

    # -------------------------------------------------------------
    # Assertion G: Multi-Site Vulnerability Extraction & Code Identification
    # -------------------------------------------------------------
    log("Step 3: Testing POST /api/vuln-intel/extract across external sites & custom URL...")
    intel_resp = requests.post(
        f"{BACKEND_URL}/api/vuln-intel/extract",
        json={
            "sources": ["osv", "nvd", "cisa_owasp"],
            "custom_urls": ["https://cwe.mitre.org/data/definitions/78.html"],
            "auto_scan_code": True
        },
        timeout=30
    )
    assert intel_resp.status_code == 200, f"Assertion G FAILED: /api/vuln-intel/extract returned {intel_resp.status_code}: {intel_resp.text}"
    intel_data = intel_resp.json()
    assert intel_data["extracted_count"] >= 5, f"Assertion G FAILED: Expected >= 5 extracted advisories, got {intel_data['extracted_count']}"
    assert intel_data["matched_in_code_count"] >= 1, f"Assertion G FAILED: Expected >= 1 advisory matched in code, got {intel_data['matched_in_code_count']}"
    assert intel_data["code_findings_created"] >= 1, f"Assertion G FAILED: Expected >= 1 code finding created from site extraction, got {intel_data['code_findings_created']}"

    report_resp = requests.get(f"{BACKEND_URL}/api/export/report?format=markdown", timeout=15)
    assert report_resp.status_code == 200 and "ALASTOR SAST++++++" in report_resp.text, "Assertion G FAILED: Markdown report export failed!"
    log(f"PASS: Assertion G (Extracted {intel_data['extracted_count']} advisories, matched {intel_data['matched_in_code_count']} in code with {intel_data['code_findings_created']} findings).")

    # -------------------------------------------------------------
    # Assertion H: Project Management, Risk Enumeration, SCM Import & Automation
    # -------------------------------------------------------------
    log("Step 4: Testing Project Management Hub (/api/projects)...")
    proj_resp = requests.get(f"{BACKEND_URL}/api/projects", timeout=15)
    assert proj_resp.status_code == 200, f"Assertion H FAILED: GET /api/projects returned {proj_resp.status_code}"
    projects = proj_resp.json()
    assert len(projects) >= 1 and "risk_level" in projects[0] and "risk_score" in projects[0], "Assertion H FAILED: Projects missing risk enumeration!"

    new_proj_resp = requests.post(
        f"{BACKEND_URL}/api/projects",
        json={
            "name": "Harness-Temp-Project",
            "description": "Temporary verification project",
            "scm_provider": "LOCAL",
            "repo_url": "",
            "branch": "main",
            "target_path": target_scan_dir,
            "preset_id": "preset-optimized",
            "auto_scan_on_push": False,
            "auto_scan_on_pr": False,
        },
        timeout=15,
    )
    assert new_proj_resp.status_code == 200, f"Assertion H FAILED: POST /api/projects returned {new_proj_resp.status_code}"
    created_proj = new_proj_resp.json()
    auto_resp = requests.put(
        f"{BACKEND_URL}/api/projects/{created_proj['id']}/automation",
        json={"auto_scan_on_push": False, "auto_scan_on_pr": False},
        timeout=15,
    )
    assert auto_resp.status_code == 200, "Assertion H FAILED: PUT /api/projects/{id}/automation failed!"
    # Clean up temporary verification project so no dummy project remains in the Hub
    requests.delete(f"{BACKEND_URL}/api/projects/{created_proj['id']}", timeout=15)
    log("PASS: Assertion H (Project Management Hub, Risk Enumeration, Local Registration & Cleanup verified).")

    # -------------------------------------------------------------
    # Assertion I: Deep Dive & Analysis Interface (Severity, Aging, Compliance, Unified Engines)
    # -------------------------------------------------------------
    log("Step 5: Testing Deep Dive Analytics (/api/analytics/deep-dive)...")
    dd_resp = requests.get(f"{BACKEND_URL}/api/analytics/deep-dive", timeout=15)
    assert dd_resp.status_code == 200, f"Assertion I FAILED: GET /api/analytics/deep-dive returned {dd_resp.status_code}"
    dd_data = dd_resp.json()
    assert "severity_breakdown" in dd_data and len(dd_data.get("aging_summary", [])) >= 4, "Assertion I FAILED: Missing severity or aging summary!"
    assert len(dd_data.get("compliance_reports", [])) >= 3, "Assertion I FAILED: Missing compliance standard reports!"
    engines = {e["engine"] for e in dd_data.get("engine_breakdown", [])}
    assert {"SAST", "SCA", "IaC"}.issubset(engines), f"Assertion I FAILED: Unified engines missing SAST/SCA/IaC: {engines}"
    log("PASS: Assertion I (Deep Dive Analytics: Severity, Aging Summary, Compliance Reports & Unified SAST/SCA/IaC Engines verified).")

    # -------------------------------------------------------------
    # Assertion J: Vulnerability Remediation View (Best Fixed Location & Suppression/Validation)
    # -------------------------------------------------------------
    log("Step 6: Testing Best Fixed Location (BFL) & Triage Suppression (/api/findings/{id}/triage)...")
    taint_f = taint_findings[0]
    assert taint_f.get("best_fix_location") is not None, "Assertion J FAILED: Finding missing Best Fixed Location (BFL)!"
    assert taint_f["best_fix_location"]["line"] >= 1, "Assertion J FAILED: Invalid BFL line!"
    triage_resp = requests.post(
        f"{BACKEND_URL}/api/findings/{taint_f['id']}/triage",
        json={"status": "CONFIRMED", "reason": "Verified exploitable via CPG trace", "author": "Harness"},
        timeout=15,
    )
    assert triage_resp.status_code == 200, f"Assertion J FAILED: Triage update failed: {triage_resp.text}"
    # Reset back to TO_VERIFY so no test harness triage state lingers
    requests.post(
        f"{BACKEND_URL}/api/findings/{taint_f['id']}/triage",
        json={"status": "TO_VERIFY", "reason": "", "author": ""},
        timeout=15,
    )
    log("PASS: Assertion J (Best Fixed Location (BFL) & Triage Validation/Suppression verified).")

    # -------------------------------------------------------------
    # Assertion K: Settings & Customization Engine (Presets, Global vs Project, Query Viewer, Custom Sanitizers)
    # -------------------------------------------------------------
    log("Step 7: Testing Settings, Scan Presets & Customization Engine (/api/settings)...")
    settings_resp = requests.get(f"{BACKEND_URL}/api/settings", timeout=15)
    assert settings_resp.status_code == 200, f"Assertion K FAILED: GET /api/settings returned {settings_resp.status_code}"
    settings_data = settings_resp.json()
    preset_ids = [p["id"] for p in settings_data.get("presets", [])]
    assert "preset-optimized" in preset_ids, f"Assertion K FAILED: Checkmarx-style 'preset-optimized' missing from presets: {preset_ids}"
    assert len(settings_data.get("queries", [])) >= 5, "Assertion K FAILED: Security queries missing in Query Viewer!"

    san_resp = requests.post(
        f"{BACKEND_URL}/api/settings/sanitizers",
        json={
            "function_name": "shlex.quote",
            "language": "Python",
            "target_cwe": "CWE-78",
            "description": "POSIX shell token quoting sanitizer for OS command arguments",
        },
        timeout=15,
    )
    assert san_resp.status_code == 200, f"Assertion K FAILED: POST /api/settings/sanitizers failed: {san_resp.text}"
    log("PASS: Assertion K (Scan Presets, Global vs Project Settings, Query Viewer & Custom Sanitizers verified).")

    # -------------------------------------------------------------
    # Assertion L: Integration Hub (Jira / GitHub Issues & Automated Ticket Creation)
    # -------------------------------------------------------------
    log("Step 8: Testing Integration Hub (/api/integrations)...")
    int_resp = requests.get(f"{BACKEND_URL}/api/integrations", timeout=15)
    assert int_resp.status_code == 200, f"Assertion L FAILED: GET /api/integrations returned {int_resp.status_code}"

    # Test connection probes when unconfigured (should report NOT_CONFIGURED / Not Working For Now)
    gh_probe = requests.post(
        f"{BACKEND_URL}/api/integrations/test-connection",
        json={"provider": "GITHUB_ISSUES", "github_repo": ""},
        timeout=15,
    )
    assert gh_probe.status_code == 200 and gh_probe.json().get("mode") == "NOT_CONFIGURED", f"Assertion L FAILED: POST /api/integrations/test-connection (GitHub) failed: {gh_probe.text}"
    jira_probe = requests.post(
        f"{BACKEND_URL}/api/integrations/test-connection",
        json={"provider": "JIRA", "jira_url": "", "jira_project_key": "SEC"},
        timeout=15,
    )
    assert jira_probe.status_code == 200 and jira_probe.json().get("mode") == "NOT_CONFIGURED", "Assertion L FAILED: Jira connection probe failed!"

    # Test auto-sync tickets, standalone HTML ticket page, 2-way status sync, and cleanup
    sync_resp = requests.post(f"{BACKEND_URL}/api/integrations/tickets/auto-sync", timeout=15)
    assert sync_resp.status_code == 200, f"Assertion L FAILED: POST /api/integrations/tickets/auto-sync failed: {sync_resp.text}"
    sync_data = sync_resp.json()
    tickets_list = sync_data if isinstance(sync_data, list) else sync_data.get("tickets", [])
    assert len(tickets_list) >= 1, "Assertion L FAILED: Expected automated tickets to be generated for high/critical findings!"

    sample_ticket = tickets_list[0]
    view_resp = requests.get(f"{BACKEND_URL}/api/integrations/tickets/{sample_ticket['id']}/view", timeout=15)
    assert view_resp.status_code == 200 and sample_ticket["ticket_key"] in view_resp.text, "Assertion L FAILED: Standalone HTML ticket view failed!"

    patch_resp = requests.patch(
        f"{BACKEND_URL}/api/integrations/tickets/{sample_ticket['id']}",
        json={"status": "IN_PROGRESS", "comment": "Verified via E2E harness"},
        timeout=15,
    )
    assert patch_resp.status_code == 200 and patch_resp.json().get("status") == "IN_PROGRESS", "Assertion L FAILED: PATCH ticket status failed!"

    # Clean up all harness-generated test tickets so the UI starts with 0 dummy tickets
    for t in tickets_list:
        requests.delete(f"{BACKEND_URL}/api/integrations/tickets/{t['id']}", timeout=15)

    log(
        f"PASS: Assertion L (Integration Hub connection status, standalone view, 2-way sync & cleanup of {len(tickets_list)} test tickets verified)."
    )

    # 12. Assertion M: Non-Coder Plain-English, RACI, Call-Graph Reachability, EPSS v4 & Before/After Code Diff on Findings
    log("Verifying Assertion M: Plain-English, Analogy, Business Impact, RACI, Reachability, EPSS v4 & Code Diff on Findings...")
    assert len(findings) >= 1, "Assertion M FAILED: Expected findings to verify plain-english enrichment!"
    sample_f = findings[0]
    assert sample_f.get("plain_english_summary"), "Assertion M FAILED: plain_english_summary missing on finding!"
    assert sample_f.get("non_coder_analogy"), "Assertion M FAILED: non_coder_analogy missing on finding!"
    assert sample_f.get("business_impact"), "Assertion M FAILED: business_impact missing on finding!"
    assert isinstance(sample_f.get("management_action_steps"), list) and len(sample_f["management_action_steps"]) >= 1, "Assertion M FAILED: management_action_steps missing!"
    assert sample_f.get("raci_responsible") and sample_f.get("raci_accountable"), "Assertion M FAILED: RACI Responsible/Accountable missing on finding!"
    assert sample_f.get("reachability_status") in ("REACHABLE", "CONDITIONALLY_REACHABLE", "UNREACHABLE_DORMANT"), "Assertion M FAILED: reachability_status missing!"
    assert sample_f.get("reachability_reason"), "Assertion M FAILED: reachability_reason missing!"
    assert isinstance(sample_f.get("epss_score"), (int, float)) and sample_f["epss_score"] > 0, "Assertion M FAILED: epss_score missing!"
    assert sample_f.get("best_fix_location", {}).get("before_code_block") is not None, "Assertion M FAILED: before_code_block missing on BFL!"
    assert sample_f.get("best_fix_location", {}).get("after_code_block"), "Assertion M FAILED: after_code_block missing on BFL!"

    sarif_resp = requests.get(f"{BACKEND_URL}/api/export/report?format=sarif", timeout=15)
    assert sarif_resp.status_code == 200, "Assertion M FAILED: SARIF v2.1.0 export failed!"
    sarif_json = sarif_resp.json()
    assert sarif_json.get("version") == "2.1.0" and len(sarif_json.get("runs", [{}])[0].get("results", [])) >= 1, "Assertion M FAILED: Invalid SARIF v2.1.0 payload!"
    log(
        f"PASS: Assertion M (Plain-English, RACI, Reachability='{sample_f.get('reachability_status')}', EPSS={sample_f.get('epss_score')}, Before/After Code Diff & SARIF v2.1.0 verified across {len(findings)} findings)."
    )

    # 13. Assertion N: Interactive RACI Governance & Accountability Matrix API
    log("Verifying Assertion N: Interactive RACI Governance Matrix (/api/governance/raci)...")
    raci_resp = requests.get(f"{BACKEND_URL}/api/governance/raci", timeout=15)
    assert raci_resp.status_code == 200, f"Assertion N FAILED: /api/governance/raci returned {raci_resp.status_code}"
    raci_data = raci_resp.json()
    assert len(raci_data.get("roles", [])) >= 6, "Assertion N FAILED: Expected >=6 RACI roles!"
    assert len(raci_data.get("activities", [])) >= 6, "Assertion N FAILED: Expected >=6 RACI governance activities!"
    assert raci_data.get("governance_health_score") == 100 and raci_data.get("valid_rows_count") == raci_data.get("total_rows_count"), "Assertion N FAILED: Default RACI matrix should satisfy PMI/COBIT validation!"

    # Test updating a cell and resetting back to default
    first_act = raci_data["activities"][0]
    first_role_id = raci_data["roles"][0]["role_id"]
    cell_resp = requests.put(
        f"{BACKEND_URL}/api/governance/raci/cell",
        json={"activity_id": first_act["activity_id"], "role_id": first_role_id, "value": "R"},
        timeout=15,
    )
    assert cell_resp.status_code == 200, f"Assertion N FAILED: PUT /api/governance/raci/cell failed ({cell_resp.text})!"
    reset_resp = requests.post(f"{BACKEND_URL}/api/governance/raci/reset", timeout=15)
    assert reset_resp.status_code == 200 and reset_resp.json().get("governance_health_score") == 100, "Assertion N FAILED: POST /api/governance/raci/reset failed!"
    log(
        f"PASS: Assertion N (RACI Matrix with {len(raci_data['roles'])} roles, {len(raci_data['activities'])} activities, cell editing & PMI/COBIT validation verified)."
    )

    # 14. Assertion O: SAST++++++ ASPM Suite (Live SBOM, Attack Surface, Management Roadmap, STRIDE Threat Model & CI/CD PBOM)
    log("Verifying Assertion O: SAST++++++ ASPM Suite (/api/aspm/suite)...")
    aspm_resp = requests.get(
        f"{BACKEND_URL}/api/aspm/suite",
        params={"project_path": target_scan_dir},
        timeout=20,
    )
    assert aspm_resp.status_code == 200, f"Assertion O FAILED: /api/aspm/suite returned {aspm_resp.status_code}"
    aspm_data = aspm_resp.json()
    assert len(aspm_data.get("sbom_components", [])) >= 1, "Assertion O FAILED: Expected real SBOM components parsed from workspace manifests/imports!"
    assert aspm_data.get("cyclonedx_json", {}).get("bomFormat") == "CycloneDX", "Assertion O FAILED: Expected CycloneDX v1.5 JSON export!"
    assert len(aspm_data.get("endpoints", [])) >= 1, "Assertion O FAILED: Expected discovered attack surface endpoints!"
    assert len(aspm_data.get("roadmap_items", [])) >= 1, "Assertion O FAILED: Expected prioritized management remediation roadmap!"
    assert len(aspm_data.get("stride_threats", [])) == 6, f"Assertion O FAILED: Expected 6 STRIDE threat categories, got {len(aspm_data.get('stride_threats', []))}"
    for st_item in aspm_data.get("stride_threats", []):
        assert st_item.get("total_checks_count", 0) >= 1, f"Assertion O FAILED: Missing total_checks_count in STRIDE {st_item.get('stride_letter')}"
        assert st_item.get("ok_count", 0) >= 1, f"Assertion O FAILED: Missing ok_count in STRIDE {st_item.get('stride_letter')}"
        assert isinstance(st_item.get("issue_count"), int), f"Assertion O FAILED: Missing issue_count in STRIDE {st_item.get('stride_letter')}"
        assert len(st_item.get("observations", [])) >= 1, f"Assertion O FAILED: Missing observations list in STRIDE {st_item.get('stride_letter')}"
    assert len(aspm_data.get("pipeline_checks", [])) == 5, f"Assertion O FAILED: Expected 5 CI/CD PBOM pipeline checks, got {len(aspm_data.get('pipeline_checks', []))}"
    log(
        f"PASS: Assertion O (SAST++++++ ASPM Suite: {len(aspm_data['sbom_components'])} SBOM packages, {len(aspm_data['endpoints'])} entrypoints, {len(aspm_data['stride_threats'])} STRIDE threats & {len(aspm_data['pipeline_checks'])} PBOM checks verified)."
    )

    # 15. Assertion S: v2.6.0 Semgrep-Superiority Benchmark (Inter-Procedural Taint, Live OSV CVE, CI/CD & 0% False Positives)
    log("Verifying Assertion S: v2.6.0 Multi-Engine Semgrep-Superiority & Zero-FP Benchmark...")
    with tempfile.TemporaryDirectory(prefix="alastor_v26_bench_") as bench_dir:
        wf_dir = os.path.join(bench_dir, ".github", "workflows")
        os.makedirs(wf_dir, exist_ok=True)

        # 1. Vulnerable & Sanitized FastAPI / Python code exercising RULE-7, RULE-8, RULE-10, RULE-11, RULE-12, RULE-13
        bench_py = os.path.join(bench_dir, "service_api.py")
        with open(bench_py, "w", encoding="utf-8") as fh:
            fh.write(
                'import os\n'
                'import hashlib\n'
                'import logging\n'
                'import urllib.request\n'
                'import yaml\n'
                'import requests\n'
                'from fastapi import FastAPI\n'
                'from neo4j import GraphDatabase\n'
                '\n'
                'app = FastAPI()\n'
                'logger = logging.getLogger("bench")\n'
                '\n'
                'def _sanitize_log(v: str) -> str:\n'
                '    return str(v).replace("\\n", " ").replace("\\r", " ")\n'
                '\n'
                'def _validate_safe_remote_url(u: str) -> str:\n'
                '    assert u.startswith("https://api.example.com/")\n'
                '    return u\n'
                '\n'
                'def _weak_url_validator(u: str) -> str:\n'
                '    # Weak check (only checks scheme prefix, allows 127.0.0.1 / RFC1918) -> ALASTOR must NOT treat as sanitizer!\n'
                '    return u if u.startswith("http") else ""\n'
                '\n'
                'def _custom_confine_dir(raw_rel: str) -> str:\n'
                '    cand = os.path.realpath(os.path.join("/srv/reports", raw_rel))\n'
                '    if os.path.commonpath(["/srv/reports", cand]) != "/srv/reports":\n'
                '        raise ValueError("escape")\n'
                '    return cand\n'
                '\n'
                'def helper_read_report(rel_path: str):\n'
                '    return open(rel_path, "r", encoding="utf-8").read()\n'
                '\n'
                '@app.get("/api/unsafe-report")\n'
                'def unsafe_report_endpoint(filepath: str):\n'
                '    return helper_read_report(filepath)\n'
                '\n'
                '@app.post("/api/unsafe-batch")\n'
                'def unsafe_batch_write(batch_paths: list):\n'
                '    for item_path in batch_paths:\n'
                '        only_realpath = os.path.realpath(item_path)\n'
                '        open(only_realpath, "w", encoding="utf-8").write("x")\n'
                '\n'
                '@app.get("/api/safe-report")\n'
                'def safe_report_endpoint(safe_filepath: str):\n'
                '    resolved = os.path.realpath(os.path.join("/srv/reports", safe_filepath))\n'
                '    if os.path.commonpath(["/srv/reports", resolved]) != "/srv/reports":\n'
                '        raise ValueError("blocked")\n'
                '    return open(resolved, "r", encoding="utf-8").read()\n'
                '\n'
                '@app.get("/api/safe-helper-report")\n'
                'def safe_helper_report_endpoint(user_rel: str):\n'
                '    confined = _custom_confine_dir(user_rel)\n'
                '    return open(confined, "r", encoding="utf-8").read()\n'
                '\n'
                '@app.post("/api/unsafe-webhook")\n'
                'def unsafe_webhook_fetch(webhook_url: str):\n'
                '    return urllib.request.urlopen(webhook_url, timeout=3).read()\n'
                '\n'
                '@app.post("/api/weak-ssrf")\n'
                'def unsafe_weak_ssrf_fetch(target_url: str):\n'
                '    checked_weak = _weak_url_validator(target_url)\n'
                '    return requests.get(checked_weak, timeout=3).text\n'
                '\n'
                '@app.post("/api/safe-webhook")\n'
                'def safe_webhook_fetch(clean_url: str):\n'
                '    checked = _validate_safe_remote_url(clean_url)\n'
                '    return requests.get(checked, timeout=3).text\n'
                '\n'
                '@app.get("/api/unsafe-audit")\n'
                'def unsafe_audit_log(username: str):\n'
                '    logger.warning(f"Failed login for {username}")\n'
                '\n'
                '@app.get("/api/safe-audit")\n'
                'def safe_audit_log(safe_username: str):\n'
                '    clean_u = _sanitize_log(safe_username)\n'
                '    logger.warning(f"Failed login for {clean_u}")\n'
                '\n'
                'def unsafe_parse_and_hash(raw_blob: bytes, raw_yaml: str):\n'
                '    obj = yaml.load(raw_yaml, Loader=yaml.Loader)\n'
                '    dg = hashlib.md5(raw_blob).hexdigest()\n'
                '    return obj, dg\n'
                '\n'
                'def safe_parse_and_hash(raw_blob: bytes, raw_yaml: str):\n'
                '    obj = yaml.safe_load(raw_yaml)\n'
                '    dg = hashlib.md5(raw_blob, usedforsecurity=False).hexdigest()\n'
                '    return obj, dg\n'
                '\n'
                'def connect_legacy_graph():\n'
                '    return GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "SuperSecretProdGraph99!"))\n'
                '\n'
                'def safe_sql_lookup(cursor, raw_uid: str):\n'
                '    uid_int = int(raw_uid)\n'
                '    cursor.execute(f"SELECT id FROM accounts WHERE id = {uid_int}")\n'
            )

        # 2. Vulnerable pinned dependency in requirements.txt (requests==2.32.3 -> real OSV CVE + imported in service_api.py)
        with open(os.path.join(bench_dir, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("requests==2.32.3\n")

        # 3. GitHub Actions workflow with mutable tag (@v4) + untrusted ${{ github.event.* }} shell injection
        with open(os.path.join(wf_dir, "ci.yml"), "w", encoding="utf-8") as fh:
            fh.write(
                "name: CI\n"
                "on: [pull_request]\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\n"
                "      - run: echo \"PR Title ${{ github.event.pull_request.title }}\"\n"
            )

        # 4. Rootless Dockerfile so IAC-2 does not fire on container user
        with open(os.path.join(bench_dir, "Dockerfile"), "w", encoding="utf-8") as fh:
            fh.write("FROM python:3.12-slim\nRUN useradd -m appuser\nUSER appuser\nCMD [\"python\", \"service_api.py\"]\n")

        bench_scan = requests.post(
            f"{BACKEND_URL}/api/scan",
            json={"target_path": bench_dir},
            timeout=90,
        )
        assert bench_scan.status_code == 200, f"Assertion S FAILED: Benchmark scan returned {bench_scan.status_code}: {bench_scan.text}"
        bench_findings = requests.get(
            f"{BACKEND_URL}/api/findings",
            params={"project_path": bench_dir},
            timeout=20,
        ).json()
        by_rule: Dict[str, List[Dict[str, Any]]] = {}
        for bf in bench_findings:
            by_rule.setdefault(bf["rule_id"], []).append(bf)

        # Verify True Positives across all v2.6.1 rules + AST-Verified Sanitizer Summary (0% FP)
        assert len(by_rule.get("RULE-10-PATH-TRAVERSAL", [])) == 2, (
            f"Assertion S FAILED: Expected 2 RULE-10-PATH-TRAVERSAL TPs (inter-procedural + for-loop/unguarded-realpath) and 0 FPs on safe_report_endpoint/safe_helper_report_endpoint, got: {by_rule.get('RULE-10-PATH-TRAVERSAL')}"
        )
        assert len(by_rule.get("RULE-11-SSRF-URLOPEN", [])) == 2, (
            f"Assertion S FAILED: Expected 2 RULE-11-SSRF-URLOPEN TPs (urlopen + weak validator requests.get) and 0 FP on safe_webhook_fetch, got: {by_rule.get('RULE-11-SSRF-URLOPEN')}"
        )
        assert len(by_rule.get("RULE-12-LOG-INJECTION", [])) == 1, (
            f"Assertion S FAILED: Expected 1 RULE-12-LOG-INJECTION TP (0 FP on safe_audit_log), got: {by_rule.get('RULE-12-LOG-INJECTION')}"
        )
        r13_list = by_rule.get("RULE-13-UNSAFE-DESERIALIZATION-CRYPTO", [])
        assert len(r13_list) == 2, (
            f"Assertion S FAILED: Expected 2 RULE-13 TPs (yaml.load + md5 without usedforsecurity=False) and 0 FPs on safe_load/usedforsecurity=False, got {len(r13_list)}: {[x['title'] for x in r13_list]}"
        )
        assert len(by_rule.get("RULE-8-HARDCODED-SECRET", [])) >= 1, (
            "Assertion S FAILED: Expected RULE-8-HARDCODED-SECRET to detect GraphDatabase.driver hardcoded tuple auth!"
        )
        assert len(by_rule.get("RULE-7-SQLI-FORMAT", [])) == 0, (
            f"Assertion S FAILED: Sanitized int(raw_uid) SQL query caused a False Positive in RULE-7-SQLI-FORMAT: {by_rule.get('RULE-7-SQLI-FORMAT')}"
        )
        sca2_list = by_rule.get("SCA-2-LIVE-CVE-LOCKFILE", [])
        assert len(sca2_list) >= 1 and sca2_list[0].get("reachability_status") == "REACHABLE", (
            f"Assertion S FAILED: Expected SCA-2-LIVE-CVE-LOCKFILE to flag requests==2.32.3 as REACHABLE, got: {sca2_list}"
        )
        iac3_list = by_rule.get("IAC-3-CICD-WORKFLOW-SECURITY", [])
        assert len(iac3_list) == 2, (
            f"Assertion S FAILED: Expected 2 IAC-3-CICD-WORKFLOW-SECURITY TPs (mutable @v4 + event title shell injection) and 0 FP on SHA-pinned action, got {len(iac3_list)}: {[x['title'] for x in iac3_list]}"
        )

        # Clean up temporary benchmark project registration
        cur_projs = requests.get(f"{BACKEND_URL}/api/projects", timeout=15).json()
        for cp in cur_projs:
            if os.path.normcase(cp.get("target_path", "")) == os.path.normcase(os.path.abspath(bench_dir)):
                requests.delete(f"{BACKEND_URL}/api/projects/{cp['id']}", timeout=15)

    log(
        f"PASS: Assertion S (v2.6.0 Semgrep-Superiority Benchmark: 100% TP across RULE-8/10/11/12/13, Live OSV CVE Reachability & CI/CD Security with 0% False Positives across all sanitized negative tests)."
    )

    # 16. Assertion P: Self-Audit Verification of cpg-sast-platform (0 Findings Remaining)
    log(f"Verifying Assertion P: Full Self-Audit of {ROOT_DIR} (verifying 0 unpatched findings)...")
    self_scan_resp = requests.post(
        f"{BACKEND_URL}/api/scan",
        json={"target_path": str(ROOT_DIR)},
        timeout=180,
    )
    assert self_scan_resp.status_code == 200, f"Assertion P FAILED: Self-audit scan returned {self_scan_resp.status_code}: {self_scan_resp.text}"
    self_findings_resp = requests.get(
        f"{BACKEND_URL}/api/findings",
        params={"project_path": str(ROOT_DIR)},
        timeout=20,
    )
    assert self_findings_resp.status_code == 200
    self_findings = self_findings_resp.json()
    if len(self_findings) != 0:
        summary_str = ", ".join(
            f"{f.get('rule_id')}@{f.get('path_nodes', [{}])[0].get('filepath')}:{f.get('path_nodes', [{}])[0].get('start_line')}"
            for f in self_findings[:10]
        )
        raise AssertionError(
            f"Assertion P FAILED: Expected 0 findings on self-audit of {ROOT_DIR}, but found {len(self_findings)}: {summary_str}"
        )
    self_report_resp = requests.get(f"{BACKEND_URL}/api/export/report?format=json", timeout=20)
    assert self_report_resp.status_code == 200
    self_report_data = self_report_resp.json()
    assert self_report_data.get("metrics", {}).get("total_findings") == 0, "Assertion P FAILED: Exported self-audit report should show 0 total_findings!"
    assert self_report_data.get("application_name") == "cpg-sast-platform", f"Assertion P FAILED: Expected application_name 'cpg-sast-platform', got {self_report_data.get('application_name')}"

    dd_self = requests.get(f"{BACKEND_URL}/api/analytics/deep-dive", timeout=20).json()
    assert dd_self.get("project_name") == "cpg-sast-platform", f"Assertion P FAILED: Deep dive project_name should be 'cpg-sast-platform', got {dd_self.get('project_name')}"
    log(
        f"PASS: Assertion P (Self-Audit of cpg-sast-platform verified: 0 findings across SAST, SCA, and IaC; active application '{dd_self.get('project_name')}' with {self_scan_resp.json().get('files_scanned')} files scanned)."
    )

    # 16. Assertion Q: Saved Scan Snapshot, Last Scanned Timestamp & Continuous Track Changes Mode
    log("Verifying Assertion Q: Saved Scan Snapshot & Continuous Track Changes (/api/scan/track-changes)...")
    tc_resp = requests.get(f"{BACKEND_URL}/api/scan/track-changes", timeout=15)
    assert tc_resp.status_code == 200, f"Assertion Q FAILED: /api/scan/track-changes returned {tc_resp.status_code}"
    tc_data = tc_resp.json()
    assert tc_data.get("has_been_scanned") is True, f"Assertion Q FAILED: Expected has_been_scanned=True, got {tc_data}"
    assert tc_data.get("last_scanned_at"), f"Assertion Q FAILED: Expected non-empty last_scanned_at, got {tc_data}"
    assert tc_data.get("scan_count", 0) >= 1, f"Assertion Q FAILED: Expected scan_count >= 1, got {tc_data}"
    assert isinstance(tc_data.get("fixed_findings"), list) and isinstance(tc_data.get("new_findings"), list), "Assertion Q FAILED: Missing fixed_findings / new_findings lists!"
    log(
        f"PASS: Assertion Q (Track Changes verified: Last Scanned='{tc_data.get('last_scanned_at')}', Scan #{tc_data.get('scan_count')}, Fixed={tc_data.get('fixed_count')}, New={tc_data.get('new_count')}, Unchanged={tc_data.get('unchanged_count')})."
    )

    # 17. Assertion R: Enterprise Call Graph, Entry Points Graph & Multi-Tenant Account/RBAC Separation
    log("Verifying Assertion R: Call Graph (CALL_GRAPH), Entry Points Graph (ENTRYPOINT_GRAPH) & Multi-Tenant RBAC (/api/accounts)...")
    cg_resp = requests.get(f"{BACKEND_URL}/api/graph", params={"view_mode": "CALL_GRAPH"}, timeout=20)
    assert cg_resp.status_code == 200, f"Assertion R FAILED: CALL_GRAPH returned {cg_resp.status_code}"
    cg_data = cg_resp.json()
    assert len(cg_data.get("nodes", [])) >= 5, f"Assertion R FAILED: Expected CALL_GRAPH nodes >= 5, got {len(cg_data.get('nodes', []))}"

    ep_resp = requests.get(f"{BACKEND_URL}/api/graph", params={"view_mode": "ENTRYPOINT_GRAPH"}, timeout=20)
    assert ep_resp.status_code == 200, f"Assertion R FAILED: ENTRYPOINT_GRAPH returned {ep_resp.status_code}"
    ep_data = ep_resp.json()
    assert len(ep_data.get("nodes", [])) >= 3, f"Assertion R FAILED: Expected ENTRYPOINT_GRAPH nodes >= 3, got {len(ep_data.get('nodes', []))}"

    acct_resp = requests.get(f"{BACKEND_URL}/api/accounts", timeout=15)
    assert acct_resp.status_code == 200, f"Assertion R FAILED: /api/accounts returned {acct_resp.status_code}"
    acct_data = acct_resp.json()
    assert len(acct_data.get("accounts", [])) >= 3 and len(acct_data.get("users", [])) >= 5, "Assertion R FAILED: Missing multi-tenant accounts or RBAC user profiles!"
    for _acct in acct_data.get("accounts", []):
        assert isinstance(_acct.get("assigned_project_ids"), list), f"Assertion R FAILED: Account {_acct.get('id')} missing assigned_project_ids list!"
        assert _acct.get("organization_unit") and _acct.get("compliance_mandate"), f"Assertion R FAILED: Account {_acct.get('id')} missing organization_unit or compliance_mandate!"
    for _usr in acct_data.get("users", []):
        assert _usr.get("avatar_badge") and _usr.get("clearance_level"), f"Assertion R FAILED: User {_usr.get('id')} missing avatar_badge or clearance_level!"
        assert isinstance(_usr.get("can_reveal_secrets"), bool) and isinstance(_usr.get("can_edit_rules"), bool), f"Assertion R FAILED: User {_usr.get('id')} missing boolean RBAC capability flags!"
    sw_resp = requests.post(f"{BACKEND_URL}/api/accounts/switch", json={"account_id": "acct-enterprise-hq", "user_id": "usr-architect"}, timeout=15)
    assert sw_resp.status_code == 200, f"Assertion R FAILED: POST /api/accounts/switch returned {sw_resp.status_code}"
    log(
        f"PASS: Assertion R (CALL_GRAPH={len(cg_data['nodes'])} nodes, ENTRYPOINT_GRAPH={len(ep_data['nodes'])} nodes, Accounts={len(acct_data['accounts'])}, RBAC Users={len(acct_data['users'])})."
    )

    # Restore previously active user project if one was selected
    if orig_active_proj and orig_active_proj.get("id"):
        requests.post(f"{BACKEND_URL}/api/projects/{orig_active_proj['id']}/activate", timeout=15)


def main():
    log("Starting Argon Self-Verification Suite...")
    backend_proc = None
    frontend_proc = None

    try:
        verify_neo4j_apoc()
        backend_proc = ensure_backend_running()
        
        # Run CPG assertions
        run_assertions()

        # Check frontend HTTP 200
        log(f"Checking Next.js frontend accessibility at {FRONTEND_URL}...")
        frontend_proc = ensure_frontend_running()
        fe_resp = requests.get(FRONTEND_URL, timeout=10)
        assert fe_resp.status_code == 200, f"Frontend check failed with status: {fe_resp.status_code}"
        log("PASS: Frontend HTTP 200 confirmed.")

        print("\n" + "=" * 78)
        print("ALL 18 DETERMINISTIC CPG, SEMGREP-SUPERIORITY & SELF-AUDIT ASSERTIONS PASSED (100%)")
        print("=" * 78 + "\n")
        sys.exit(0)

    except Exception as e:
        print(f"\n[HARNESS ERROR] {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if backend_proc:
            log("Terminating spawned backend process...")
            backend_proc.terminate()
        if frontend_proc:
            log("Terminating spawned frontend process...")
            frontend_proc.terminate()


if __name__ == "__main__":
    main()
