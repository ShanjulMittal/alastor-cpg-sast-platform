import io
import json
import os
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

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
    assert cfg.masked_api_key == "••••••••9876"

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

    for bad_url in (
        "file:///etc/passwd",
        "https://10.0.0.8/v1",
        "https://192.168.1.20/v1",
        "https://172.16.4.2/v1",
        "https://metadata.google.internal/v1",
    ):
        with pytest.raises(ValueError, match="Unsupported or unsafe"):
            engine.update_config(
                AiConfigUpdateRequest(
                    provider="openai_compatible",
                    model="local-model",
                    base_url=bad_url,
                    api_key="dummy",
                    persist_key=False,
                )
            )

    # Explicit loopback for Ollama/vLLM on openai_compatible is permitted
    loopback_cfg = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai_compatible",
            model="llama3.2",
            base_url="http://localhost:11434/v1",
            api_key="",
            persist_key=False,
        )
    )
    assert loopback_cfg.provider == "openai_compatible"
    assert "localhost:11434" in loopback_cfg.base_url


def test_batch_validate_and_sha256_cache_hit(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    _cfg = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai",
            model="gpt-4o-mini",
            api_key="dummy_key_for_unit_test_1234",
            persist_key=False,
        )
    )
    assert _cfg.has_api_key is True
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

    def test_fake_dispatch_cache(system_prompt: str, user_prompt: str, expect_json: bool = True):
        call_counter["count"] += 1
        return {"text": canned_json, "prompt_tokens": 180, "completion_tokens": 65}

    with patch.object(engine, "_dispatch_provider_call", side_effect=test_fake_dispatch_cache):
        res1 = engine.validate_findings([finding], [str(tmp_path)])
        assert res1.ok is True
        assert len(res1.verdicts) == 1
        assert res1.verdicts[0].verdict == "TRUE_POSITIVE"
        assert res1.verdicts[0].cache_hit is False
        assert res1.token_telemetry.cache_hits == 0
        assert call_counter["count"] == 1

        # Second call with identical code slice MUST hit SHA-256 cache with 0 network calls
        res2 = engine.validate_findings([finding], [str(tmp_path)])
        assert res2.ok is True
        assert res2.verdicts[0].cache_hit is True
        assert res2.token_telemetry.cache_hits == 1
        assert call_counter["count"] == 1


def test_audit_code_selection_confines_workspace_path(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    _cfg = engine.update_config(
        AiConfigUpdateRequest(
            provider="anthropic",
            model="claude-3-5-haiku-latest",
            api_key="dummy_key_for_unit_test_5678",
            persist_key=False,
        )
    )
    assert _cfg.has_api_key is True
    _make_sample_finding(tmp_path)
    outside = tmp_path.parent / "outside_target.py"
    outside.write_text("x = 1\n", encoding="utf-8")

    res_blocked = engine.audit_code_selection(
        AiCodeAuditRequest(filepath="../outside_target.py", start_line=1, end_line=1),
        [str(tmp_path)],
    )
    assert res_blocked.ok is False
    assert "outside" in (res_blocked.user_message or "").lower() or "not found" in (res_blocked.user_message or "").lower()


def test_vault_persist_false_and_masked_key_preservation(tmp_path: Path):
    vault_dir = tmp_path / ".alastor_vault"
    engine = FrontierAiEngine(vault_dir=str(vault_dir))
    ephemeral_val = "session_only_credential_4321"
    cfg_mem = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai",
            model="gpt-4o-mini",
            api_key=ephemeral_val,
            persist_key=False,
        )
    )
    assert cfg_mem.has_api_key is True
    assert cfg_mem.masked_api_key == "••••••••4321"
    cfg_file = vault_dir / "ai_config.json"
    if cfg_file.exists():
        assert ephemeral_val not in cfg_file.read_text(encoding="utf-8")

    # Updating model while passing masked placeholder or empty key preserves existing session credential
    cfg_kept = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai",
            model="gpt-4o",
            api_key="••••••••4321",
            persist_key=False,
        )
    )
    assert cfg_kept.has_api_key is True
    assert cfg_kept.model == "gpt-4o"
    assert cfg_kept.masked_api_key == "••••••••4321"

    # Persisting key reloads cleanly on a new instance without exposing raw key in public config
    persisted_val = "persisted_vault_credential_7788"
    _cfg_saved = engine.update_config(
        AiConfigUpdateRequest(
            provider="gemini",
            model="gemini-2.5-flash",
            api_key=persisted_val,
            persist_key=True,
        )
    )
    assert _cfg_saved.masked_api_key == "••••••••7788"
    reloaded = FrontierAiEngine(vault_dir=str(vault_dir)).get_public_config()
    assert reloaded.has_api_key is True
    assert reloaded.masked_api_key == "••••••••7788"
    assert persisted_val not in reloaded.model_dump_json()


def test_multi_provider_urlopen_adapters_and_error_scrubbing(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    seen_requests = []

    class _FakeHttpResp:
        def __init__(self, payload: dict):
            self._raw = json.dumps(payload).encode("utf-8")

        def read(self):
            return self._raw

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def test_fake_urlopen(req_obj, timeout=28):
        seen_requests.append((req_obj, timeout))
        full_url = req_obj.full_url
        if "generativelanguage.googleapis.com" in full_url:
            return _FakeHttpResp({
                "candidates": [{"content": {"parts": [{"text": '{"ok": true}'}]}}],
                "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 4},
            })
        if "api.anthropic.com" in full_url:
            return _FakeHttpResp({
                "content": [{"type": "text", "text": '{"ok": true}'}],
                "usage": {"input_tokens": 14, "output_tokens": 5},
            })
        return _FakeHttpResp({
            "choices": [{"message": {"content": '{"ok": true}'}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3},
        })

    with patch("urllib.request.urlopen", side_effect=test_fake_urlopen):
        _g = engine.update_config(
            AiConfigUpdateRequest(provider="gemini", model="gemini-2.5-flash", api_key="gem_unit_cred_1111", persist_key=False)
        )
        assert _g.provider == "gemini"
        ping_gem = engine.test_connection()
        assert ping_gem.ok is True
        gem_req = seen_requests[-1][0]
        assert gem_req.get_header("X-goog-api-key") == "gem_unit_cred_1111"
        assert "gem_unit_cred_1111" not in gem_req.full_url

        _a = engine.update_config(
            AiConfigUpdateRequest(provider="anthropic", model="claude-3-5-haiku-latest", api_key="ant_unit_cred_2222", persist_key=False)
        )
        assert _a.provider == "anthropic"
        ping_ant = engine.test_connection()
        assert ping_ant.ok is True
        ant_req = seen_requests[-1][0]
        assert ant_req.get_header("X-api-key") == "ant_unit_cred_2222"
        assert ant_req.get_header("Anthropic-version") == "2023-06-01"

    def test_fake_401(req_obj, timeout=28):
        raise urllib.error.HTTPError(
            url=req_obj.full_url,
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"invalid_key"}'),
        )

    with patch("urllib.request.urlopen", side_effect=test_fake_401):
        ping_fail = engine.test_connection()
        assert ping_fail.ok is False
        assert ping_fail.error_code == "AUTH_FAILED"
        assert "ant_unit_cred_2222" not in ping_fail.message


def test_fastapi_ai_endpoints_integration(tmp_path: Path):
    import main

    finding = _make_sample_finding(tmp_path)
    iso_engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    prev_scan_dir = main.current_scan_dir
    main.current_scan_dir = str(tmp_path)
    try:
        with (
            patch.object(main, "frontier_ai_engine", iso_engine),
            patch.object(main, "get_or_compute_findings", return_value=[finding]),
        ):
            client = TestClient(main.app)

            # 1. GET /api/ai/config
            r_get = client.get("/api/ai/config")
            assert r_get.status_code == 200
            body_get = r_get.json()
            assert body_get["has_api_key"] is False
            assert len(body_get["available_providers"]) >= 4
            assert "total_tokens_saved" in body_get["token_telemetry"]

            # 2. POST /api/ai/config rejects SSRF with HTTP 400
            r_bad = client.post(
                "/api/ai/config",
                json={
                    "provider": "openai_compatible",
                    "model": "m",
                    "base_url": "http://169.254.169.254/latest/",
                    "api_key": "dummy_9999",
                    "persist_key": False,
                },
            )
            assert r_bad.status_code == 400

            # Valid POST /api/ai/config
            r_cfg = client.post(
                "/api/ai/config",
                json={
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "api_key": "route_test_credential_8899",
                    "persist_key": False,
                },
            )
            assert r_cfg.status_code == 200
            assert r_cfg.json()["masked_api_key"] == "••••••••8899"
            assert "route_test_credential" not in r_cfg.text

            vulnerable_line = finding.best_fix_location.code_snippet if finding.best_fix_location else ""

            def test_fake_route_dispatch(system_prompt: str, user_prompt: str, expect_json: bool = True):
                if "verdicts" in system_prompt:
                    payload = {
                        "verdicts": [{
                            "finding_id": "FIND-CMDI-1",
                            "verdict": "TRUE_POSITIVE",
                            "confidence": 0.94,
                            "exploitability_summary": "Command runner receives unvalidated host argument.",
                            "recommended_action": "Pass fixed argument list without subshell invocation.",
                            "suggested_triage_status": "CONFIRMED",
                        }]
                    }
                elif "observations" in system_prompt:
                    payload = {
                        "summary": "Command injection sink identified in selection.",
                        "risk_level": "CRITICAL",
                        "observations": [{
                            "line_range": "L41-L42",
                            "severity": "CRITICAL",
                            "title": "Subshell command interpolation",
                            "explanation": "Untrusted host reaches subshell.",
                            "remediation": "Pass list argv without subshell.",
                        }],
                        "secure_snippet": "return ['ping', '-c', '1', user_host]",
                    }
                elif "after_snippet" in system_prompt:
                    payload = {
                        "explanation": "Replaced subshell interpolation with parameterized argv list.",
                        "before_snippet": f"    cmd = f'ping -c 1 {{user_host}}'\n    {vulnerable_line}",
                        "after_snippet": "    return ['ping', '-c', '1', user_host]",
                    }
                elif "plain_english_story" in system_prompt:
                    payload = {
                        "headline": "HTTP Host Input Reaches OS Command Sink",
                        "plain_english_story": "User query data enters run_ping and executes in a subshell.",
                        "step_walkthrough": ["Step 1: Read host param", "Step 2: Invoke command sink"],
                        "security_takeaway": "Eliminate subshell invocation and pass a fixed argument list.",
                    }
                else:
                    payload = {"ok": True}
                return {"text": json.dumps(payload), "prompt_tokens": 120, "completion_tokens": 55}

            with patch.object(iso_engine, "_dispatch_provider_call", side_effect=test_fake_route_dispatch):
                # 3. POST /api/ai/test-connection
                r_conn = client.post("/api/ai/test-connection")
                assert r_conn.status_code == 200
                assert r_conn.json()["ok"] is True

                # 4. POST /api/ai/validate-findings
                r_val = client.post("/api/ai/validate-findings", json={"finding_ids": [], "max_batch": 5})
                assert r_val.status_code == 200
                val_json = r_val.json()
                assert val_json["ok"] is True
                assert val_json["verdicts"][0]["finding_id"] == "FIND-CMDI-1"
                assert val_json["verdicts"][0]["suggested_triage_status"] == "CONFIRMED"

                # 5. POST /api/ai/audit-code-selection
                r_aud = client.post(
                    "/api/ai/audit-code-selection",
                    json={"filepath": "runner.py", "start_line": 40, "end_line": 43, "focus_question": "Check command safety"},
                )
                assert r_aud.status_code == 200
                aud_json = r_aud.json()
                assert aud_json["ok"] is True
                assert aud_json["risk_level"] == "CRITICAL"
                assert len(aud_json["observations"]) == 1

                # 6. POST /api/ai/synthesize-patch
                r_pat = client.post("/api/ai/synthesize-patch", json={"finding_id": "FIND-CMDI-1"})
                assert r_pat.status_code == 200
                pat_json = r_pat.json()
                assert pat_json["ok"] is True
                assert pat_json["finding_id"] == "FIND-CMDI-1"
                assert "['ping', '-c', '1', user_host]" in (pat_json["patched_full_content"] or "")

                # 7. POST /api/ai/explain-graph
                r_exp = client.post(
                    "/api/ai/explain-graph",
                    json={
                        "view_mode": "FINDING_PATH",
                        "finding_id": "FIND-CMDI-1",
                        "nodes_digest": [{"id": "n1", "name": "user_host"}, {"id": "n2", "name": "subprocess.Popen"}],
                        "edges_digest": [{"source": "n1", "target": "n2", "type": "DFG_FLOWS_TO"}],
                    },
                )
                assert r_exp.status_code == 200
                exp_json = r_exp.json()
                assert exp_json["ok"] is True
                assert len(exp_json["step_walkthrough"]) == 2
    finally:
        main.current_scan_dir = prev_scan_dir
