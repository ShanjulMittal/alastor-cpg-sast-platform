import http.client
import http.server
import io
import json
import os
import threading
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


def test_cross_provider_and_host_credential_isolation_and_clear(tmp_path: Path):
    vault_dir = tmp_path / ".alastor_vault"
    engine = FrontierAiEngine(vault_dir=str(vault_dir))

    # 1. Set Gemini credential, then switch to openai_compatible with omitted key -> must NOT carry credential
    _c1 = engine.update_config(
        AiConfigUpdateRequest(
            provider="gemini",
            model="gemini-2.5-flash",
            api_key="gem_unit_cred_9876",
            persist_key=False,
        )
    )
    assert _c1.has_api_key is True
    switched_none = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai_compatible",
            model="llama3.2",
            base_url="https://compat-a.example.com/v1",
            api_key=None,
            persist_key=False,
        )
    )
    assert switched_none.has_api_key is False
    assert switched_none.masked_api_key == ""

    # 2. Set OpenAI credential, then switch to loopback openai_compatible passing stale UI mask -> must NOT leak Authorization header
    _c2 = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai",
            model="gpt-4o-mini",
            api_key="oai_unit_cred_5544",
            persist_key=False,
        )
    )
    assert _c2.has_api_key is True
    switched_masked = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai_compatible",
            model="llama3.2",
            base_url="http://localhost:11434/v1",
            api_key="••••••••5544",
            persist_key=False,
        )
    )
    assert switched_masked.has_api_key is False
    assert switched_masked.masked_api_key == ""

    captured_headers = []

    class _DummyOkResp:
        def read(self):
            return b'{"choices":[{"message":{"content":"{\\"ok\\":true}"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def test_capture_urlopen(req_obj, timeout=28):
        captured_headers.append(dict(req_obj.header_items()))
        return _DummyOkResp()

    with patch("urllib.request.urlopen", side_effect=test_capture_urlopen):
        _ping = engine.test_connection()
        assert _ping.ok is True
    assert len(captured_headers) == 1
    assert "Authorization" not in captured_headers[0]

    # 3. Switching openai_compatible host with masked placeholder must also drop prior host's credential
    _c3 = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai_compatible",
            model="qwen",
            base_url="https://compat-a.example.com/v1",
            api_key="compat_a_cred_3322",
            persist_key=False,
        )
    )
    assert _c3.has_api_key is True
    switched_host = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai_compatible",
            model="qwen",
            base_url="https://compat-b.example.com/v1",
            api_key="••••••••3322",
            persist_key=False,
        )
    )
    assert switched_host.has_api_key is False

    # 4. Explicit clearing via api_key="" and via clear_api_key=True revokes memory + persisted vault key
    _c4 = engine.update_config(
        AiConfigUpdateRequest(
            provider="anthropic",
            model="claude-3-5-haiku-latest",
            api_key="ant_persisted_cred_1199",
            persist_key=True,
        )
    )
    assert _c4.has_api_key is True
    cleared_empty = engine.update_config(
        AiConfigUpdateRequest(
            provider="anthropic",
            model="claude-3-5-haiku-latest",
            api_key="",
            persist_key=True,
        )
    )
    assert cleared_empty.has_api_key is False
    assert cleared_empty.masked_api_key == ""
    assert FrontierAiEngine(vault_dir=str(vault_dir)).get_public_config().has_api_key is False

    _c5 = engine.update_config(
        AiConfigUpdateRequest(
            provider="anthropic",
            model="claude-3-5-haiku-latest",
            api_key="ant_persisted_cred_6677",
            persist_key=True,
        )
    )
    assert _c5.has_api_key is True
    cleared_flag = engine.update_config(
        AiConfigUpdateRequest(
            provider="anthropic",
            model="claude-3-5-haiku-latest",
            api_key="••••••••6677",
            persist_key=True,
            clear_api_key=True,
        )
    )
    assert cleared_flag.has_api_key is False
    assert FrontierAiEngine(vault_dir=str(vault_dir)).get_public_config().has_api_key is False


def test_redirect_ssrf_blocked_and_url_normalization_edge_cases(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))

    # 1. Trailing DNS dot on metadata/internal hosts and query/fragment injection rejected at config time
    for unsafe_candidate in (
        "https://metadata.google.internal./v1",
        "https://service.internal./v1",
        "https://compat.example.com/v1? leaked=1",
        "https://compat.example.com/v1?x=1",
        "https://compat.example.com/v1#frag",
    ):
        with pytest.raises(ValueError, match="Unsupported or unsafe"):
            engine.update_config(
                AiConfigUpdateRequest(
                    provider="openai_compatible",
                    model="m",
                    base_url=unsafe_candidate,
                    persist_key=False,
                )
            )

    # 2. Live loopback HTTP server returning 302 -> cloud metadata IP MUST be blocked without following redirect
    class _RedirectToMetadataHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or "0")
            if length > 0:
                _ = self.rfile.read(length)
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RedirectToMetadataHandler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()
    try:
        _rcfg = engine.update_config(
            AiConfigUpdateRequest(
                provider="openai_compatible",
                model="local-redirect-test",
                base_url=f"http://127.0.0.1:{port}/v1",
                persist_key=False,
            )
        )
        assert _rcfg.provider == "openai_compatible"
        redir_res = engine.test_connection()
        assert redir_res.ok is False
        assert redir_res.error_code == "REDIRECT_BLOCKED"
    finally:
        srv.shutdown()
        srv.server_close()

    # 3. Gemini leading 'models/' prefix + trailing '/v1beta' base_url normalized without double-encoding
    seen_urls = []

    class _GemResp:
        def read(self):
            return b'{"candidates":[{"content":{"parts":[{"text":"{\\"ok\\":true}"}]}}],"usageMetadata":{"promptTokenCount":6,"candidatesTokenCount":2}}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def test_gem_url_capture(req_obj, timeout=28):
        seen_urls.append(req_obj.full_url)
        return _GemResp()

    _gcfg = engine.update_config(
        AiConfigUpdateRequest(
            provider="gemini",
            model="models/gemini-2.5-flash",
            base_url="https://generativelanguage.googleapis.com/v1beta",
            api_key="gem_norm_cred_2468",
            persist_key=False,
        )
    )
    assert _gcfg.provider == "gemini"
    with patch("urllib.request.urlopen", side_effect=test_gem_url_capture):
        _gping = engine.test_connection()
        assert _gping.ok is True
    assert seen_urls == [
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    ]


def test_http_client_disconnect_and_oserror_handled_gracefully(tmp_path: Path):
    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    _cfg = engine.update_config(
        AiConfigUpdateRequest(
            provider="openai",
            model="gpt-4o-mini",
            api_key="oai_net_cred_1357",
            persist_key=False,
        )
    )
    assert _cfg.has_api_key is True
    finding = _make_sample_finding(tmp_path)

    def test_raise_remote_disconnected(req_obj, timeout=28):
        raise http.client.RemoteDisconnected("Remote end closed connection without response")

    with patch("urllib.request.urlopen", side_effect=test_raise_remote_disconnected):
        conn_res = engine.test_connection()
        assert conn_res.ok is False
        assert conn_res.error_code == "NETWORK_ERROR"
        assert "oai_net_cred_1357" not in conn_res.message

    def test_raise_conn_reset(req_obj, timeout=28):
        raise ConnectionResetError("Connection reset by peer")

    with patch("urllib.request.urlopen", side_effect=test_raise_conn_reset):
        val_res = engine.validate_findings([finding], [str(tmp_path)])
        assert val_res.ok is False
        assert val_res.error_code == "NETWORK_ERROR"
        assert "oai_net_cred_1357" not in (val_res.user_message or "")


def test_micro_slice_cross_file_context_and_no_suffix_collision(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    runner_lines = [f"# filler line {i}" for i in range(1, 80)]
    runner_lines[11] = "    marker = 'WRONG_LINE_12_IN_RUNNER'"
    runner_lines[40] = "def execute_job(cmd_arg):"
    runner_lines[41] = "    return run_safe_wrapper(cmd_arg)"
    (src_dir / "runner.py").write_text("\n".join(runner_lines), encoding="utf-8")

    auth_lines = [f"# auth line {i}" for i in range(1, 30)]
    auth_lines[11] = "    tainted_host = request.args.get('host')"
    (src_dir / "auth_runner.py").write_text("\n".join(auth_lines), encoding="utf-8")

    n_cross = CPGNode(
        id="nc1",
        label="Assignment",
        ast_type="assign",
        name="tainted_host",
        code="tainted_host = request.args.get('host')",
        filepath="src\\auth_runner.py",
        start_line=12,
        end_line=12,
        start_col=4,
        end_col=43,
        scope_id="handle_req",
        is_source=True,
        is_sink=False,
        is_sanitizer=False,
    )
    n_sink = CPGNode(
        id="nc2",
        label="Call",
        ast_type="call",
        name="run_safe_wrapper",
        code="return run_safe_wrapper(cmd_arg)",
        filepath="src\\runner.py",
        start_line=42,
        end_line=42,
        start_col=4,
        end_col=36,
        scope_id="execute_job",
        is_source=False,
        is_sink=True,
        is_sanitizer=False,
    )
    cross_finding = Finding(
        id="FIND-CROSS-1",
        rule_id="RULE-1",
        severity="HIGH",
        title="Cross-File Taint Flow",
        description="Source in auth_runner flows to sink in runner.",
        cwe_id="CWE-78",
        path_nodes=[n_cross, n_sink],
        path_edges=[{"id": "ec1", "source": "nc1", "target": "nc2", "type": "DFG_FLOWS_TO", "var_name": "tainted_host"}],
        best_fix_location=BestFixLocation(
            node_id="nc2",
            filepath="src/runner.py",
            line=42,
            column=4,
            code_snippet="return run_safe_wrapper(cmd_arg)",
            explanation="Sanitize cmd_arg",
            recommended_fix="Validate allowlist",
        ),
    )

    engine = FrontierAiEngine(vault_dir=str(tmp_path / ".alastor_vault"))
    slice_info = engine.build_cpg_micro_slice(cross_finding, [str(tmp_path)])
    text = slice_info["slice_text"]

    assert "WRONG_LINE_12_IN_RUNNER" not in text
    assert "[Cross-file src/auth_runner.py:L12] tainted_host = request.args.get('host')" in text
    assert "src/auth_runner.py:L12 --[DFG_FLOWS_TO:tainted_host]--> L42" in text
    assert "L41: def execute_job(cmd_arg):" in text
    assert "L42:     return run_safe_wrapper(cmd_arg)" in text

    # Also verify bare basename suffix-collision case: 'auth_runner.py' must NOT match 'runner.py'
    bare_finding = Finding(
        id="FIND-CROSS-2",
        rule_id="RULE-1",
        severity="HIGH",
        title="Basename Suffix Collision Check",
        description="Bare auth_runner.py must not match runner.py.",
        cwe_id="CWE-78",
        path_nodes=[
            CPGNode(
                id="nb1",
                label="Assignment",
                ast_type="assign",
                name="tainted_host",
                code="tainted_host = request.args.get('host')",
                filepath="auth_runner.py",
                start_line=12,
                end_line=12,
                start_col=4,
                end_col=43,
                scope_id="handle_req",
                is_source=True,
                is_sink=False,
                is_sanitizer=False,
            ),
            CPGNode(
                id="nb2",
                label="Call",
                ast_type="call",
                name="run_safe_wrapper",
                code="return run_safe_wrapper(cmd_arg)",
                filepath="runner.py",
                start_line=42,
                end_line=42,
                start_col=4,
                end_col=36,
                scope_id="execute_job",
                is_source=False,
                is_sink=True,
                is_sanitizer=False,
            ),
        ],
        path_edges=[{"id": "eb1", "source": "nb1", "target": "nb2", "type": "DFG_FLOWS_TO", "var_name": "tainted_host"}],
        best_fix_location=BestFixLocation(
            node_id="nb2",
            filepath="runner.py",
            line=42,
            column=4,
            code_snippet="return run_safe_wrapper(cmd_arg)",
            explanation="Sanitize cmd_arg",
            recommended_fix="Validate allowlist",
        ),
    )
    bare_slice = engine.build_cpg_micro_slice(bare_finding, [str(src_dir)])
    assert "WRONG_LINE_12_IN_RUNNER" not in bare_slice["slice_text"]
    assert "[Cross-file auth_runner.py:L12] tainted_host = request.args.get('host')" in bare_slice["slice_text"]
