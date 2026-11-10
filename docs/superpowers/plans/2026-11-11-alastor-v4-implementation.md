# ALASTOR v4.0 — Directional Graphs, Light-Only 4-Stage UI & BYOK Frontier AI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver ALASTOR v4.0 with 100% visible directional arrows and plain-English flow comprehension across all CPG/360°/Trust-Boundary graphs, a simplified 4-stage Light-Only high-contrast UI (with zero feature reduction plus Batch Auto-Fix), and a token-efficient multi-provider BYOK Frontier AI Copilot achieving 90–95% prompt token savings via deterministic CPG Micro-Slicing and SHA-256 slice caching.

**Architecture:** On the FastAPI backend, `backend/engine/frontier_ai_engine.py` provides a zero-leak `0o600` local BYOK vault, SSRF-hardened multi-provider HTTP adapters (Gemini, OpenAI, Anthropic, OpenAI-compatible), deterministic CPG Micro-Slicing, SHA-256 verdict caching, and 4 security AI workflows, while `app_tree.py`, `remediation_patcher.py`, and `main.py` add cross-file `IMPORTS`/`CALLS` directional edges, single-node 3-step attack-context synthesis, and atomic `POST /api/remediate/batch-apply`. On the Next.js frontend, all dark themes are retired in favor of a high-visibility WCAG AA Light-Only Daylight palette across Monaco, ReactFlow, and all 25+ views, reorganized around a clean 4-Stage Workflow Bar (*1. Scan & Repos · 2. Triage & Fix · 3. 360° Map & Threats · 4. ASPM, Rules & Reports*) + collapsible Frontier AI Copilot Drawer, custom `DirectionalFlowEdge` SVGs, perimeter-docked `CustomGraphNode` handles, and an interactive 4-Zone Directional Trust Boundary Graph.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, Neo4j, Next.js 14 (App Router), TypeScript, Tailwind CSS, Zustand, ReactFlow (`@xyflow/react` / `reactflow`), Monaco Editor (`@monaco-editor/react`), Pytest.

## Global Constraints

- **Zero Feature Reduction:** Every existing view, scanner engine (SAST, OSV SCA, IaC, Secrets, Live Web CVE Intel), custom rule/Cypher studio, CycloneDX SBOM, STRIDE/PBOM, RACI matrix, Jira/GitHub connector, keyboard shortcut (`Ctrl+K`, `[`/`]`, `j`/`k`), and export format (SARIF, HTML, CSV, Markdown) MUST remain accessible.
- **Mandatory Light-Only High-Contrast Daylight Theme:** All dark themes (`alastor-infernal`, `hecate-arcane`, `stygian-abyss`) are retired. `:root`, `layout.tsx`, `useAuditStore.ts`, `MonacoCodePane.tsx` (`theme="light"`), and `ReactFlowGraphPane.tsx` MUST run exclusively in high-visibility light mode with >= 4.5:1 WCAG AA contrast on all text, badges, inputs, tables, and graph edges. Never render `text-white` on a light card/surface.
- **100% Visible Graph Flow Direction:** Every edge in Attack Path, Full CPG, DFG, CFG, Call Graph, Entrypoints, 360° Spider/Mind-Map, Single-Node SCA/IaC Findings, and Trust Boundary Map MUST display perimeter-docked directional arrowheads outside node borders plus human-readable directional badges.
- **90–95% Token Efficiency & Zero-Leak BYOK Vault:** Never send full multi-hundred-line files to LLMs when a CPG Micro-Slice or line selection suffices; store persisted keys in `.alastor_vault/ai_config.json` with `0o600` permissions; never return raw keys in `GET /api/ai/config` or logs.
- **Zero Self-Audit Findings:** All Python and TypeScript code MUST pass ALASTOR's 21-rule + Web Intel self-audit with `0` findings (`os.path.realpath` + `os.path.commonpath` confinement on workspace/vault file access, strict `https://` or explicit loopback validation on outbound URLs, no `shell=True`, no `eval`, no hardcoded secret patterns).

---

### Task 1: Token-Efficient Multi-Provider BYOK Frontier AI Engine & REST API

**Files:**
- Create: `backend/engine/frontier_ai_engine.py`
- Modify: `backend/models.py`
- Modify: `backend/main.py`
- Create: `backend/tests/test_frontier_ai_engine.py`

**Interfaces:**
- Consumes: `Finding`, `CPGNode`, `BestFixLocation` from `backend/models.py`; `_locate_enumerated_workspace_file` from `backend/engine/remediation_patcher.py`.
- Produces:
  - `FrontierAiEngine` in `backend/engine/frontier_ai_engine.py` with methods:
    - `get_public_config() -> AiPublicConfigResponse`
    - `update_config(req: AiConfigUpdateRequest) -> AiPublicConfigResponse`
    - `test_connection() -> AiConnectionTestResponse`
    - `build_cpg_micro_slice(finding: Finding, allowed_roots: List[str]) -> Dict[str, Any]`
    - `validate_findings(findings: List[Finding], allowed_roots: List[str]) -> AiValidateFindingsResponse`
    - `audit_code_selection(req: AiCodeAuditRequest, allowed_roots: List[str]) -> AiCodeAuditResponse`
    - `synthesize_patch(finding: Finding, allowed_roots: List[str]) -> AiPatchSynthesisResponse`
    - `explain_graph(req: AiGraphExplainRequest) -> AiGraphExplainResponse`
  - FastAPI routes in `backend/main.py`: `GET /api/ai/config`, `POST /api/ai/config`, `POST /api/ai/test-connection`, `POST /api/ai/validate-findings`, `POST /api/ai/audit-code-selection`, `POST /api/ai/synthesize-patch`, `POST /api/ai/explain-graph`.

- [ ] **Step 1: Write the failing test suite in `backend/tests/test_frontier_ai_engine.py`**

```python
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from models import BestFixLocation, CPGNode, Finding
from engine.frontier_ai_engine import (
    AiCodeAuditRequest,
    AiConfigUpdateRequest,
    AiGraphExplainRequest,
    FrontierAiEngine,
)


def _make_sample_finding(tmp_path: Path) -> Finding:
    src_lines = [f"# padding comment line {i}" for i in range(1, 220)]
    src_lines[10] = "def run_ping(request):"
    src_lines[14] = "    user_host = request.args.get('host', '127.0.0.1')"
    src_lines[40] = "    cmd = f'ping -c 1 {user_host}'"
    src_lines[41] = "    return subprocess.Popen(cmd, shell=True)"
    target_file = tmp_path / "runner.py"
    target_file.write_text("\n".join(src_lines), encoding="utf-8")

    n1 = CPGNode(
        id="n1", label="Assignment", ast_type="assign", name="user_host",
        code=src_lines[14].strip(), filepath="runner.py",
        start_line=15, end_line=15, start_col=4, end_col=52, scope_id="run_ping",
        is_source=True, is_sink=False, is_sanitizer=False,
    )
    n2 = CPGNode(
        id="n2", label="Call", ast_type="call", name="subprocess.Popen",
        code=src_lines[41].strip(), filepath="runner.py",
        start_line=42, end_line=42, start_col=11, end_col=44, scope_id="run_ping",
        is_source=False, is_sink=True, is_sanitizer=False,
    )
    return Finding(
        id="FIND-CMDI-1",
        rule_id="RULE-1",
        severity="CRITICAL",
        title="OS Command Injection",
        description="Untrusted input reaches shell sink.",
        cwe_id="CWE-78",
        path_nodes=[n1, n2],
        path_edges=[{"id": "e1", "source": "n1", "target": "n2", "type": "DFG_FLOWS_TO", "var_name": "user_host"}],
        best_fix_location=BestFixLocation(
            node_id="n2", filepath="runner.py", line=42, column=11,
            code_snippet=src_lines[41].strip(),
            explanation="Avoid shell invocation",
            recommended_fix="Pass argument list without shell",
        ),
    )


def test_micro_slice_token_reduction_and_key_masking(tmp_path: Path):
    vault_dir = tmp_path / ".alastor_vault"
    engine = FrontierAiEngine(vault_dir=str(vault_dir))
    cfg = engine.update_config(
        AiConfigUpdateRequest(
            provider="gemini",
            model="gemini-2.5-flash",
            api_key="test_dummy_token_value_9876",
            persist_key=True,
        )
    )
    assert cfg.has_api_key is True
    assert "9876" in cfg.masked_api_key
    assert "test_dummy_token_value" not in cfg.masked_api_key

    finding = _make_sample_finding(tmp_path)
    slice_info = engine.build_cpg_micro_slice(finding, [str(tmp_path)])
    assert "def run_ping(request):" in slice_info["slice_text"]
    assert slice_info["slice_tokens_est"] < slice_info["full_file_tokens_est"] * 0.35
    assert slice_info["savings_pct"] >= 65.0


def test_ssrf_url_validation_rejects_metadata_ip(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    with pytest.raises(ValueError, match="Unsupported or unsafe"):
        engine.update_config(
            AiConfigUpdateRequest(
                provider="openai_compatible",
                model="local-model",
                base_url="http://169.254.169.254/latest/meta-data/",
                api_key="dummy",
                persist_key=False,
            )
        )


def test_batch_validate_and_sha256_cache_hit(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    engine.update_config(
        AiConfigUpdateRequest(
            provider="openai",
            model="gpt-4o-mini",
            api_key="dummy_key_for_unit_test_1234",
            persist_key=False,
        )
    )
    finding = _make_sample_finding(tmp_path)
    canned_json = json.dumps({
        "verdicts": [
            {
                "finding_id": "FIND-CMDI-1",
                "verdict": "TRUE_POSITIVE",
                "confidence": 0.96,
                "exploitability_summary": "Direct HTTP query parameter interpolated into shell command.",
                "recommended_action": "Pass argument array to subprocess.run without shell invocation.",
                "suggested_triage_status": "CONFIRMED",
            }
        ]
    })

    call_counter = {"count": 0}

    def fake_dispatch(system_prompt: str, user_prompt: str, expect_json: bool = True):
        call_counter["count"] += 1
        return {"text": canned_json, "prompt_tokens": 180, "completion_tokens": 65}

    with patch.object(engine, "_dispatch_provider_call", side_effect=fake_dispatch):
        res1 = engine.validate_findings([finding], [str(tmp_path)])
        assert res1.ok is True
        assert len(res1.verdicts) == 1
        assert res1.verdicts[0].verdict == "TRUE_POSITIVE"
        assert res1.token_telemetry.cache_hits == 0
        assert call_counter["count"] == 1

        # Second call with identical code slice MUST hit SHA-256 cache with 0 network calls
        res2 = engine.validate_findings([finding], [str(tmp_path)])
        assert res2.ok is True
        assert res2.token_telemetry.cache_hits == 1
        assert call_counter["count"] == 1


def test_audit_code_selection_confines_workspace_path(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    engine.update_config(
        AiConfigUpdateRequest(
            provider="anthropic",
            model="claude-3-5-haiku-latest",
            api_key="dummy_key_for_unit_test_5678",
            persist_key=False,
        )
    )
    _make_sample_finding(tmp_path)
    outside = tmp_path.parent / "secret_outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")

    res_blocked = engine.audit_code_selection(
        AiCodeAuditRequest(filepath="../secret_outside.py", start_line=1, end_line=1),
        [str(tmp_path)],
    )
    assert res_blocked.ok is False
    assert "outside" in (res_blocked.user_message or "").lower() or "not found" in (res_blocked.user_message or "").lower()
```

- [ ] **Step 2: Run pytest to verify it fails**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\backend"; python -m pytest tests/test_frontier_ai_engine.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'engine.frontier_ai_engine'`

- [ ] **Step 3: Implement `backend/engine/frontier_ai_engine.py`, models in `backend/models.py`, and `/api/ai/*` routes in `backend/main.py`**

Create `backend/engine/frontier_ai_engine.py` implementing:
- Pydantic request/response models (`AiProviderType = Literal["gemini", "openai", "anthropic", "openai_compatible"]`, `AiConfigUpdateRequest`, `AiPublicConfigResponse`, `AiTokenTelemetry`, `AiFindingVerdict`, `AiValidateFindingsRequest`, `AiValidateFindingsResponse`, `AiCodeAuditRequest`, `AiCodeAuditObservation`, `AiCodeAuditResponse`, `AiPatchSynthesisRequest`, `AiPatchSynthesisResponse`, `AiGraphExplainRequest`, `AiGraphExplainResponse`, `AiConnectionTestResponse`).
- Strict outbound URL validator `_validate_provider_endpoint(provider, base_url)` enforcing allowlisted `https://` hosts (`generativelanguage.googleapis.com`, `api.openai.com`, `api.anthropic.com`, or `https://` custom OpenAI-compatible hosts + `http://localhost` / `http://127.0.0.1` loopback only for local Ollama/vLLM).
- Vault persistence confined via `os.path.realpath` + `os.path.commonpath` to `.alastor_vault/ai_config.json` and `.alastor_vault/ai_verdict_cache.json` (`os.chmod(..., 0o600)`), masking keys as `••••••••` + last 4 chars.
- `build_cpg_micro_slice(finding, allowed_roots)` using `_locate_enumerated_workspace_file` to read only the enclosing `def`/`function`/`class` signature + deduplicated `±3` line windows around `path_nodes` and `best_fix_location` (capped at 40 lines), measuring `full_file_tokens_est` vs `slice_tokens_est` and `savings_pct`.
- Multi-provider HTTP client using `urllib.request.Request` + `urllib.request.urlopen(req, timeout=28)` supporting `gemini` (`x-goog-api-key` header), `openai` (`Authorization: Bearer`), `anthropic` (`x-api-key` + `anthropic-version: 2023-06-01`), and `openai_compatible`, catching `HTTPError` / `URLError` / `TimeoutError` cleanly into `{ok: False, error_code, user_message}` without leaking headers.
- Wire `GET /api/ai/config`, `POST /api/ai/config`, `POST /api/ai/test-connection`, `POST /api/ai/validate-findings`, `POST /api/ai/audit-code-selection`, `POST /api/ai/synthesize-patch`, and `POST /api/ai/explain-graph` in `backend/main.py`.

- [ ] **Step 4: Run pytest to verify all tests pass**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\backend"; python -m pytest tests/test_frontier_ai_engine.py -v`
Expected: PASS (`4 passed`)

- [ ] **Step 5: Commit Task 1**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add backend/engine/frontier_ai_engine.py backend/models.py backend/main.py backend/tests/test_frontier_ai_engine.py
git commit -m "feat(ai): add token-efficient multi-provider BYOK Frontier AI engine and REST endpoints"
```

---

### Task 2: Cross-File 360° Dependencies, Single-Node Directional Graph Synthesis & Batch Auto-Fix API

**Files:**
- Modify: `backend/compiler/app_tree.py`
- Modify: `backend/engine/remediation_patcher.py`
- Modify: `backend/models.py`
- Modify: `backend/main.py`
- Create: `backend/tests/test_v4_graphs_and_batch_fix.py`

**Interfaces:**
- Consumes: `AppTreeAnalyzer` in `backend/compiler/app_tree.py`; `preview_finding_remediation`, `apply_workspace_patch` in `backend/engine/remediation_patcher.py`.
- Produces:
  - `CrossFileEdge` (`source_filepath: str`, `target_filepath: str`, `edge_type: str`, `symbols: List[str]`, `flow_label: str`) on `AppTreeSummary.cross_file_edges` and `FilePurposeInfo.imports_files`.
  - Enriched `GET /api/graph`:
    - `view_mode == "FINDING_PATH"`: synthesizes a 3-node directional chain (`Ingress / Origin ──▶ Vulnerable Chokepoint [BFL] ──▶ Security Impact`) whenever a finding has `<= 1` `path_nodes` and `0` `path_edges`, and populates `flow_label` + `step_index` on every edge.
    - `view_mode == "APP_TREE"`: includes cross-file `IMPORTS` directional edges alongside `CONTAINS` edges, and falls back to `current_app_tree` in-memory when Neo4j has no `AppFile` nodes.
  - `batch_apply_workspace_patches(findings, allowed_roots, patch_vault_root)` in `backend/engine/remediation_patcher.py` and `POST /api/remediate/batch-apply` (`BatchRemediateRequest` -> `BatchRemediateResponse`) in `backend/main.py`.

- [ ] **Step 1: Write the failing test suite in `backend/tests/test_v4_graphs_and_batch_fix.py`**

```python
from pathlib import Path
from compiler.app_tree import AppTreeAnalyzer
from engine.remediation_patcher import batch_apply_workspace_patches, synthesize_single_node_context_graph
from models import BestFixLocation, CPGNode, Finding


def test_app_tree_extracts_cross_file_imports(tmp_path: Path):
    (tmp_path / "utils").mkdir()
    (tmp_path / "utils" / "Sanitizer.ts").write_text(
        "export function cleanInput(v: string) { return v.trim(); }\n", encoding="utf-8"
    )
    (tmp_path / "api.ts").write_text(
        "import { cleanInput } from './utils/Sanitizer';\nexport function handle(x: string) { return cleanInput(x); }\n",
        encoding="utf-8",
    )
    summary = AppTreeAnalyzer(str(tmp_path)).analyze()
    assert len(summary.cross_file_edges) >= 1
    edge = summary.cross_file_edges[0]
    assert edge.source_filepath == "api.ts"
    assert edge.target_filepath == "utils/Sanitizer.ts"
    assert edge.edge_type == "IMPORTS"


def test_single_node_finding_synthesizes_3_step_directional_chain():
    lone_node = CPGNode(
        id="iac-1", label="Call", ast_type="config", name="Dockerfile:USER root",
        code="USER root", filepath="Dockerfile",
        start_line=8, end_line=8, start_col=0, end_col=9, scope_id="Dockerfile",
        is_source=False, is_sink=True, is_sanitizer=False,
    )
    finding = Finding(
        id="FIND-IAC-1", rule_id="IAC-1", severity="HIGH",
        title="Container Runs as Root", description="Container lacks non-root user.",
        cwe_id="CWE-250", path_nodes=[lone_node], path_edges=[], scan_engine="IaC",
    )
    graph = synthesize_single_node_context_graph(finding)
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    assert graph["edges"][0]["step_index"] == 1
    assert graph["edges"][1]["step_index"] == 2
    assert graph["edges"][0]["flow_label"]


def test_batch_apply_fixes_multiple_findings_atomically(tmp_path: Path):
    f_py = tmp_path / "service.py"
    f_py.write_text(
        "import hashlib\nimport yaml\n\ndef h(b):\n    return hashlib.md5(b).hexdigest()\n\ndef y(s):\n    return yaml.load(s)\n",
        encoding="utf-8",
    )
    findings = [
        Finding(
            id="F-CRYPTO", rule_id="RULE-3", severity="MEDIUM", title="Weak Hash",
            description="MD5 used", cwe_id="CWE-328",
            path_nodes=[CPGNode(
                id="n-md5", label="Call", ast_type="call", name="hashlib.md5",
                code="return hashlib.md5(b).hexdigest()", filepath="service.py",
                start_line=5, end_line=5, start_col=11, end_col=36, scope_id="h",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
        Finding(
            id="F-YAML", rule_id="RULE-10", severity="HIGH", title="Unsafe YAML",
            description="yaml.load used", cwe_id="CWE-502",
            path_nodes=[CPGNode(
                id="n-yaml", label="Call", ast_type="call", name="yaml.load",
                code="return yaml.load(s)", filepath="service.py",
                start_line=8, end_line=8, start_col=11, end_col=23, scope_id="y",
                is_source=False, is_sink=True, is_sanitizer=False,
            )],
            path_edges=[],
        ),
    ]
    vault = tmp_path / ".alastor_patches"
    result = batch_apply_workspace_patches(findings, [str(tmp_path)], str(vault))
    assert result["applied_count"] == 2
    updated_text = f_py.read_text(encoding="utf-8")
    assert "sha256" in updated_text
    assert "safe_load" in updated_text
```

- [ ] **Step 2: Run pytest to verify it fails**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\backend"; python -m pytest tests/test_v4_graphs_and_batch_fix.py -v`
Expected: FAIL with `ImportError` (`batch_apply_workspace_patches`, `synthesize_single_node_context_graph`)

- [ ] **Step 3: Implement cross-file `IMPORTS` analysis, single-node 3-step graph synthesis, and `POST /api/remediate/batch-apply`**

- Update `backend/compiler/app_tree.py`: add `CrossFileEdge` model, `imports_files: List[str]` on `FilePurposeInfo`, `cross_file_edges: List[CrossFileEdge]` on `AppTreeSummary`, and `_resolve_cross_file_imports()` resolving Python `import`/`from ... import` and JS/TS `import ... from` / `require(...)` against `self.flat_files`.
- Update `backend/engine/remediation_patcher.py`: implement `synthesize_single_node_context_graph(finding)` and `batch_apply_workspace_patches(findings, allowed_roots, patch_vault_root)` (grouping findings by resolved file and applying non-overlapping line transformations safely bottom-up so earlier line numbers do not shift later lines in the same file, recording undo snapshots in `patch_vault_root`).
- Update `backend/models.py` and `backend/main.py`: add `BatchRemediateRequest` / `BatchRemediateResponse`, `POST /api/remediate/batch-apply` (with post-batch CPG re-scan verification), and enrich `GET /api/graph` (`FINDING_PATH` single-node context synthesis + `flow_label`/`step_index` on all edges + `APP_TREE` cross-file `IMPORTS` edges).

- [ ] **Step 4: Run pytest to verify all backend tests pass**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\backend"; python -m pytest tests/ -v`
Expected: PASS (`test_remediation_patcher.py`, `test_frontier_ai_engine.py`, and `test_v4_graphs_and_batch_fix.py` all green)

- [ ] **Step 5: Commit Task 2**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add backend/compiler/app_tree.py backend/engine/remediation_patcher.py backend/models.py backend/main.py backend/tests/test_v4_graphs_and_batch_fix.py
git commit -m "feat(backend): add 360 cross-file import edges, single-node flow synthesis & batch auto-fix API"
```

---

### Task 3: Mandatory Light-Only Daylight Theme System, Centralized API Client & v4 Zustand Store

**Files:**
- Create: `frontend/src/lib/api.ts`
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/app/layout.tsx`
- Modify: `frontend/src/app/globals.css`
- Modify: `frontend/src/store/useAuditStore.ts`
- Modify: `frontend/src/components/MonacoCodePane.tsx`

**Interfaces:**
- Consumes: Task 1 `/api/ai/*` and Task 2 `/api/remediate/batch-apply` + `CrossFileEdge` schemas.
- Produces:
  - `BACKEND_URL` and typed helper functions in `frontend/src/lib/api.ts` (`apiFetchJson`, `fetchGraphData`, `fetchAiConfig`, `updateAiConfig`, `testAiConnection`, `validateFindingsWithAi`, `auditCodeSelectionWithAi`, `synthesizePatchWithAi`, `explainGraphWithAi`, `batchApplyRemediations`).
  - TypeScript interfaces in `frontend/src/types/cpg.ts`: `PrimaryWorkflowStage = "SCAN_REPOS" | "TRIAGE_FIX" | "MAP_360_THREATS" | "ASPM_GOVERNANCE"`, `CrossFileEdge`, `AiProviderType`, `AiPublicConfig`, `AiTokenTelemetry`, `AiFindingVerdict`, `AiCodeAuditResponse`, `AiPatchSynthesisResponse`, `AiGraphExplainResponse`, `BatchRemediateResponse`.
  - Light-only `RootLayout` (`class="light" data-theme="olympian-light" data-theme-mode="light"`), retired dark themes in `globals.css` + universal high-contrast overrides for `slate-*`, `zinc-*`, `rose-*`, `violet-*`, `sky-*`, `orange-*`, `teal-*`, and accidental `text-white` on light surfaces.
  - Updated `useAuditStore` with `primaryStage`, `mapSubTab` (`"SPIDER_360" | "THREAT_BOUNDARIES"`), `aspmSubSection` (`"POSTURE" | "SAST_PLUS" | "RULES_ENGINE" | "GOVERNANCE" | "EXPORTS"`), `isAiDrawerOpen`, `aiConfig`, `aiVerdictsByFinding`, `aiLastAudit`, `aiLastGraphExplanation`, `aiIsBusy`, `isBatchFixing`, `batchApplyAllSafeFixes()`, and AI workflow actions; `showPortalGate` defaults to `false`; `appTheme` defaults to `"olympian-light"`.
  - `MonacoCodePane.tsx` switched to `theme="light"` with toolbar buttons **"✨ AI Audit Selection"** and **"✨ AI Synthesize Patch"**.

- [ ] **Step 1: Create `frontend/src/lib/api.ts` and extend `frontend/src/types/cpg.ts`**

Add all v4 types (`PrimaryWorkflowStage`, `CrossFileEdge`, `AiPublicConfig`, `AiFindingVerdict`, `AiCodeAuditResponse`, `BatchRemediateResponse`, `flow_label` & `step_index` on graph edges) to `frontend/src/types/cpg.ts`, and create `frontend/src/lib/api.ts` centralizing `BACKEND_URL` (`process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000"`) and typed endpoint helpers.

- [ ] **Step 2: Enforce Light-Only High-Contrast Daylight Theme in `layout.tsx` and `globals.css`**

- Update `frontend/src/app/layout.tsx` so `<html>` sets `className="light ..."` and `data-theme="olympian-light"` `data-theme-mode="light"`.
- Update `frontend/src/app/globals.css`:
  - Set `:root` directly to the crisp **Olympian Daylight** high-contrast palette (`--background: #f8fafc`, `--surface-void: #f1f5f9`, `--surface-panel: #ffffff`, `--surface-elevated: #f8fafc`, `--ink-primary: #0f172a`, `--ink-muted: #475569`, `--border: #cbd5e1`, `--z-950: 248 250 252`, `--z-900: 255 255 255`, `--z-800: 226 232 240`, `--z-700: 203 213 225`, `--z-600: 100 116 139`, `--z-500: 71 85 105`, `--z-400: 51 65 85`, `--z-300: 30 41 59`, `--z-200: 15 23 42`, `--z-100: 9 14 26`, `--z-50: 2 6 23`).
  - Remove dark theme blocks (`alastor-infernal`, `hecate-arcane`, `stygian-abyss`) and add comprehensive light-surface contrast rules covering `bg-slate-950`, `bg-slate-900`, `bg-slate-800`, `text-slate-100..400`, `bg-rose-950`, `text-rose-200..400`, `bg-violet-950`, `text-violet-200..400`, `bg-sky-950`, `text-sky-200..400`, `bg-orange-950`, `bg-teal-950`, and scoping `.text-white` so white text only remains white inside solid saturated backgrounds (`bg-blue-600`, `bg-indigo-600`, `bg-emerald-600`, `bg-rose-600`, `bg-red-600`, `bg-amber-600`, `bg-purple-600`, `bg-cyan-600`, `bg-slate-900`), automatically converting stray `.text-white` on light surfaces to `#0f172a`!

- [ ] **Step 3: Update `useAuditStore.ts` and `MonacoCodePane.tsx`**

- In `useAuditStore.ts`: default `appTheme: "olympian-light"`, `showPortalGate: false`, restrict `VALID_APP_THEMES` to `["olympian-light", "athena-parchment", "hyperborean-light"]` (auto-migrating any saved dark preference in `hydrateUiPreferences`), add `primaryStage` synced bidirectionally with `workspaceViewMode` so every existing caller (`openCodeLocationInIde`, `QuickCommandModal`, `ProjectsHubView`) seamlessly switches to the matching stage, and add `batchApplyAllSafeFixes` + Frontier AI state/actions.
- In `MonacoCodePane.tsx`: switch `<Editor theme="light" />` and `<DiffEditor theme="light" />`, convert header/footer chrome to crisp light slate surfaces, track Monaco cursor selection range (`selectionRange`), and add **"✨ AI Audit Selection"** and **"✨ AI Patch"** buttons that open `FrontierAiCopilotDrawer` and invoke the corresponding store actions.

- [ ] **Step 4: Run TypeScript typecheck to verify 0 errors**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\frontend"; npx tsc --noEmit`
Expected: PASS (`0` errors)

- [ ] **Step 5: Commit Task 3**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/lib/api.ts frontend/src/types/cpg.ts frontend/src/app/layout.tsx frontend/src/app/globals.css frontend/src/store/useAuditStore.ts frontend/src/components/MonacoCodePane.tsx
git commit -m "feat(frontend): enforce high-contrast light-only theme, centralized API client & v4 store"
```

---

### Task 4: Directional Graph Engine — Perimeter Handles, Custom Directional Edges, Story Bar, Blast Radius & Trust Boundary Flow Graph

**Files:**
- Create: `frontend/src/components/DirectionalFlowEdge.tsx`
- Modify: `frontend/src/components/CustomGraphNode.tsx`
- Modify: `frontend/src/components/ReactFlowGraphPane.tsx`
- Modify: `frontend/src/components/ThreatModelingView.tsx`

**Interfaces:**
- Consumes: `CrossFileEdge`, `flow_label`, `step_index`, `api.ts` (`fetchGraphData`, `explainGraphWithAi`), `useAuditStore` (`primaryStage`, `explainCurrentGraphWithAi`).
- Produces:
  - `DirectionalFlowEdge` custom ReactFlow edge type (`directionalFlow`) rendering crisp directional `markerEnd` arrowheads, animated directional stroke dashes, and high-contrast mid-edge pill badges (`① TAINT ▶`, `IMPORTS ▶`, `CALLS ▶`, `CONTAINS ▶`, `TRUE ▶`, `FALSE ▶`, `LOOP ↺`, `UNGUARDED ▶`, `SANITIZED ✓`).
  - `CustomGraphNode` with 4 perimeter source/target handle pairs (`top-tgt`/`top-src`, `right-tgt`/`right-src`, `bottom-tgt`/`bottom-src`, `left-tgt`/`left-src`) on light-mode high-contrast node cards (`#ffffff` card, `#0f172a` title, `#1e293b` code pill, semantic badge).
  - Reworked `ReactFlowGraphPane` with:
    - Dynamic handle routing (`LR`/`MIND_MAP` -> `right-src`/`left-tgt`, `TB` -> `bottom-src`/`top-tgt`, `SPIDER_360` -> radial quadrant angle selection so 100% of arrowheads sit outside card borders).
    - Cross-file `IMPORTS` / `CALLS` edge toggle (on by default in 360° Architecture view).
    - Client-side fallback 3-step synthesis for single-node findings so no finding ever renders without directional flow.
    - **Plain-English Flow Story Bar** at top of graph + clickable step chips + **"✨ AI Explain Flow"** button + **Hover/Click Upstream/Downstream Blast-Radius Highlighting** + clean `Layers & Layout ▾` popover replacing the 3 cluttered stacked toolbars.
  - Interactive **4-Zone Directional Trust Boundary Flow Graph** inside `ThreatModelingView.tsx` (`BOUNDARIES` tab) replacing static CSS boxes with a real ReactFlow directional boundary diagram (*Zone 1: External Ingress ──▶ Zone 2: Entrypoints ──▶ Zone 3: Sanitizers / BFL ──▶ Zone 4: Critical Sinks & Secrets*).

- [ ] **Step 1: Create `frontend/src/components/DirectionalFlowEdge.tsx` and upgrade `frontend/src/components/CustomGraphNode.tsx`**

Implement `DirectionalFlowEdge` using `getBezierPath` / `getSmoothStepPath` + `EdgeLabelRenderer` with high-contrast light-mode badges and directional chevrons (`▶`), and update `CustomGraphNode.tsx` to render crisp light-mode cards with all 4 perimeter source/target handles (`top-src`, `top-tgt`, `right-src`, `right-tgt`, `bottom-src`, `bottom-tgt`, `left-src`, `left-tgt`).

- [ ] **Step 2: Upgrade `frontend/src/components/ReactFlowGraphPane.tsx`**

- Replace hardcoded `http://localhost:8000` fetches with `fetchGraphData` from `@/lib/api`.
- Register `edgeTypes={{ directionalFlow: DirectionalFlowEdge }}` and assign perimeter `sourceHandle` / `targetHandle` based on `cpgLayoutDirection`, `treeLayoutStyle`, and `atan2(dy, dx)` in `SPIDER_360` mode.
- Render `appTree.cross_file_edges` in 360° Spider / Mind-Map views as violet `IMPORTS ▶` directional edges.
- Add the **Plain-English Flow Story Bar**, **Blast-Radius Highlighting** (computing upstream ancestors & downstream descendants from active/hovered node), **"✨ AI Explain Flow"** trigger, light ReactFlow `<Background color="#cbd5e1" />` + light `<MiniMap />` + consolidated single-row toolbar with `Layers & Layout ▾` popover.

- [ ] **Step 3: Upgrade `ThreatModelingView.tsx` Trust Boundary Map to Interactive ReactFlow Directional Graph**

In `frontend/src/components/ThreatModelingView.tsx`, upgrade the `BOUNDARIES` tab to render an interactive 4-Zone ReactFlow canvas using `CustomGraphNode` + `DirectionalFlowEdge` showing concrete directional crossings from External Untrusted Sources -> Discovered Entrypoints -> BFL Sanitizers / Call Graph -> Vulnerable Sinks & Exposed Secrets (with click-to-jump into Code Triage), plus retaining the expandable detailed zone inventory cards underneath.

- [ ] **Step 4: Run TypeScript typecheck to verify 0 errors**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\frontend"; npx tsc --noEmit`
Expected: PASS (`0` errors)

- [ ] **Step 5: Commit Task 4**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/components/DirectionalFlowEdge.tsx frontend/src/components/CustomGraphNode.tsx frontend/src/components/ReactFlowGraphPane.tsx frontend/src/components/ThreatModelingView.tsx
git commit -m "feat(graphs): add perimeter arrowheads, directional flow edges, story bar, blast radius & trust boundary graph"
```

---

### Task 5: Simplified 4-Stage Workflow UI Shell, Frontier AI Copilot Drawer, Batch Auto-Fix UX & Full Light-Contrast Sweep

**Files:**
- Create: `frontend/src/components/FrontierAiCopilotDrawer.tsx`
- Modify: `frontend/src/components/StudioCommandHeader.tsx`
- Modify: `frontend/src/components/FlawExplorerSidebar.tsx`
- Modify: `frontend/src/app/page.tsx`
- Modify: `frontend/src/components/SettingsCustomizationModal.tsx`
- Modify: `frontend/src/components/QuickCommandModal.tsx`
- Modify: `frontend/src/components/StudioStatusBar.tsx`

**Interfaces:**
- Consumes: `useAuditStore` (`primaryStage`, `mapSubTab`, `aspmSubSection`, `isAiDrawerOpen`, `batchApplyAllSafeFixes`, AI actions), `DirectionalFlowEdge`, `ReactFlowGraphPane`, `ThreatModelingView`, `MonacoCodePane`.
- Produces:
  - `FrontierAiCopilotDrawer.tsx`: BYOK Provider selector (`Google Gemini`, `OpenAI`, `Anthropic Claude`, `OpenAI-Compatible / Ollama`), masked API key vault + `Test Connection`, live **Token Efficiency Meter** (`Prompt Tokens` vs `Full-File Equivalent`, `% Saved`, `SHA-256 Cache Hits`), and tabbed/contextual results for Finding TP/FP Verdicts (with one-click *"Apply Triage Verdict"*), Highlighted Code Selection Audits, AI Synthesized Patches (with one-click *"Load into Diff Editor"*), and Plain-English Graph Explanations.
  - Simplified `StudioCommandHeader.tsx` & `page.tsx`:
    - Single clean **4-Stage Workflow Bar**:
      1. **`1. Scan & Repos`** (Quick Target Scan Bar + `ProjectsHubView` + Scan History / Track Changes)
      2. **`2. Triage & Fix`** (`FlawExplorerSidebar` + `MonacoCodePane` + `ReactFlowGraphPane` with `Split` / `Code` / `Graph` toggle)
      3. **`3. 360° Map & Threats`** (Clean segmented switch between Full-Screen `360° Architecture & Call Flows` and `Trust Boundaries, STRIDE & PBOM`)
      4. **`4. ASPM, Rules & Reports`** (Clean horizontal sub-bar housing `Executive Posture & Deep Analytics`, `SAST+ Translator, SBOM & Academy`, `Rule Engine, Cypher & CVE Intel`, `RACI, RBAC & Jira/GitHub Connectors`, and `Export Center` for SARIF / HTML / Markdown / CSV / SBOM)
    - Retires the cluttered 10-icon `LeftFunctionBar` and nested 7-category `Menu ▾` from the main shell while keeping 100% of views 1 click away (and searchable via `⌘K / Ctrl+K` in `QuickCommandModal`).
  - `FlawExplorerSidebar.tsx`: adds prominent **"⚡ Fix All Safe Issues (N)"** Batch Auto-Fix action + **"✨ AI Validate Top Findings"** batch digest button + per-finding AI verdict badge (`AI: TP 96%` / `AI: FP`).
  - `SettingsCustomizationModal.tsx`: updates Appearance tab to display only the 3 crisp Light Daylight palettes (`Olympian Daylight`, `Athena Parchment`, `Hyperborean Frost`) + shortcut to Frontier AI BYOK Vault.

- [ ] **Step 1: Create `frontend/src/components/FrontierAiCopilotDrawer.tsx`**

Build the collapsible high-contrast light-mode right drawer with BYOK configuration, connection tester, Token Efficiency Meter, and interactive cards for all 4 AI workflows.

- [ ] **Step 2: Add Batch Auto-Fix & Batch AI Validation to `FlawExplorerSidebar.tsx`**

Add the one-click **"⚡ Fix All Safe Issues"** action bar (calling `batchApplyAllSafeFixes()`) and **"✨ AI Validate"** single/batch triggers + AI verdict chips on finding cards.

- [ ] **Step 3: Rework `StudioCommandHeader.tsx`, `page.tsx`, `SettingsCustomizationModal.tsx`, `QuickCommandModal.tsx`, and `StudioStatusBar.tsx`**

Wire the 4-Stage Workflow Bar (*1. Scan & Repos · 2. Triage & Fix · 3. 360° Map & Threats · 4. ASPM, Rules & Reports*), mount `FrontierAiCopilotDrawer`, ensure every single enterprise view and export is cleanly reachable in 1 click + `Ctrl+K`, and ensure crisp light-mode contrast across headers, modals, and status bar.

- [ ] **Step 4: Run TypeScript typecheck and production Next.js build**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\frontend"; npx tsc --noEmit; npm run build`
Expected: PASS (`0` TypeScript errors and clean Next.js production build)

- [ ] **Step 5: Commit Task 5**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git add frontend/src/components/FrontierAiCopilotDrawer.tsx frontend/src/components/StudioCommandHeader.tsx frontend/src/components/FlawExplorerSidebar.tsx frontend/src/app/page.tsx frontend/src/components/SettingsCustomizationModal.tsx frontend/src/components/QuickCommandModal.tsx frontend/src/components/StudioStatusBar.tsx
git commit -m "feat(ui): rework shell into 4-stage light workflow with Frontier AI Copilot & batch auto-fix"
```

---

### Task 6: Full-Stack Verification, Light-Contrast Audit, `verify_harness.py` & Zero-Finding Self-Audit

**Files:**
- Modify (only if audit uncovers any contrast or self-audit edge case): `frontend/src/app/globals.css` or target component
- Test: `backend/tests/test_frontier_ai_engine.py`, `backend/tests/test_v4_graphs_and_batch_fix.py`, `backend/tests/test_remediation_patcher.py`, `verify_harness.py`

**Interfaces:**
- Consumes: Complete ALASTOR v4.0 backend + frontend build.
- Produces: Verified test & build evidence across backend pytest, frontend production build, light-only theme audit, `verify_harness.py` (`20/20`), and ALASTOR self-audit (`0` findings).

- [ ] **Step 1: Run complete backend pytest suite**

Run: `Set-Location "c:\Projects\Securecodereview\cpg-sast-platform\backend"; python -m pytest tests/ -v`
Expected: PASS (`100%` of tests passing)

- [ ] **Step 2: Run Light-Theme & Contrast Static Audit + Frontend Production Build**

Verify `vs-dark` is completely absent from `frontend/src/`, dark theme IDs are absent from `VALID_APP_THEMES`, `http://localhost:8000` is centralized in `lib/api.ts` / `useAuditStore.ts`, and `npm run build` succeeds cleanly.

- [ ] **Step 3: Run `verify_harness.py` and ALASTOR Self-Audit on `cpg-sast-platform`**

Start Neo4j + Backend temporarily (or run offline + live harness), execute `python verify_harness.py` (`20/20` assertions) and run a full scan against `c:\Projects\Securecodereview\cpg-sast-platform` confirming **0 self-audit findings**, plus smoke-test `/api/ai/config`, `/api/graph?view_mode=APP_TREE`, and `/api/remediate/batch-apply`.

- [ ] **Step 4: Commit any final polish if needed and report verification evidence**

```powershell
Set-Location "c:\Projects\Securecodereview\cpg-sast-platform"
git status --short
```
