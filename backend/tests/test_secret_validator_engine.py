import base64
import io
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


def _b64url_json(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _build_jwt(exp_epoch: int, iss: str = "https://auth.internal.corp", sub: str = "svc-deploy") -> str:
    hdr = _b64url_json({"alg": "HS256", "typ": "JWT"})
    body = _b64url_json({"iss": iss, "sub": sub, "exp": exp_epoch, "iat": exp_epoch - 3600})
    sig = base64.urlsafe_b64encode(b"deterministic_hmac_sig_bytes_32!").decode("ascii").rstrip("=")
    return f"{hdr}.{body}.{sig}"


class _MockHttpResponse:
    def __init__(self, status: int, body_obj, headers: dict | None = None):
        self.status = status
        self.code = status
        if isinstance(body_obj, (dict, list)):
            self._bytes = json.dumps(body_obj).encode("utf-8")
        elif isinstance(body_obj, str):
            self._bytes = body_obj.encode("utf-8")
        else:
            self._bytes = bytes(body_obj)
        self.headers = headers or {"Content-Type": "application/json"}

    def read(self) -> bytes:
        return self._bytes

    def getcode(self) -> int:
        return self.status

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _MockOpener:
    def __init__(self, handler_fn):
        self._handler_fn = handler_fn
        self.calls: list[tuple[urllib.request.Request, float]] = []

    def open(self, req: urllib.request.Request, timeout: float = 4.0):
        self.calls.append((req, timeout))
        return self._handler_fn(req, timeout)


def test_live_200_github_verification_promotes_critical(tmp_path: Path):
    from engine.secret_validator_engine import SecretValidatorEngine
    from models import BestFixLocation, Finding

    gh_tok = "ghp_" + ("a1B2" * 9)

    def _handle_gh(req: urllib.request.Request, timeout: float):
        assert req.full_url == "https://api.github.com/user"
        assert timeout <= 4.0
        auth_hdr = req.get_header("Authorization") or ""
        assert auth_hdr == f"Bearer {gh_tok}"
        return _MockHttpResponse(
            200,
            {"login": "secops-bot", "id": 4242, "type": "User"},
            headers={"X-OAuth-Scopes": "repo, read:org"},
        )

    mock_opener = _MockOpener(_handle_gh)
    eng = SecretValidatorEngine(platform_root=str(tmp_path))

    src_dir = tmp_path / "app_repo"
    src_dir.mkdir()
    app_py = src_dir / "client.py"
    app_py.write_text(f'GH_CRED = "{gh_tok}"\n', encoding="utf-8")

    existing = Finding(
        id="FIND-GH-1",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="HIGH",
        title="Hardcoded GitHub Credential",
        description="Exposed token in client.py",
        cwe_id="CWE-798",
        is_secret_finding=True,
        secret_key_name="GH_CRED",
        secret_value_raw=gh_tok,
        path_nodes=[
            {
                "id": "n-gh-1",
                "label": "Assignment",
                "name": "GH_CRED",
                "code": 'GH_CRED = "..."',
                "filepath": "client.py",
                "start_line": 1,
                "end_line": 1,
            }
        ],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id="n-gh-1",
            filepath="client.py",
            line=1,
            column=0,
            code_snippet='GH_CRED = "..."',
            explanation="Move token to environment variable",
            recommended_fix='os.environ["GH_CRED"]',
        ),
    )

    with patch.object(eng, "_build_http_opener", return_value=mock_opener):
        validated = eng.scan_and_validate_workspace(
            str(src_dir), [existing], allow_live=True, force_refresh=True
        )

    assert len(mock_opener.calls) == 1
    matched = [f for f in validated if f.id == "FIND-GH-1"]
    assert len(matched) == 1
    f_out = matched[0]
    assert f_out.secret_validation_status == "VERIFIED_ACTIVE"
    assert f_out.secret_detector_id == "github_pat"
    assert f_out.secret_verified_identity is not None
    assert "@secops-bot" in f_out.secret_verified_identity
    assert "repo" in f_out.secret_verified_identity
    assert f_out.severity == "CRITICAL"
    assert f_out.secret_verified_at is not None


def test_live_401_openai_and_aws_sigv4_verification(tmp_path: Path):
    from engine.secret_validator_engine import SecretValidatorEngine

    oai_tok = "sk-proj-" + ("x9Y8" * 10)
    slack_tok = "xoxb-" + "123456789012" + "-" + "987654321098" + "-" + ("AbCdEf12" * 3)
    aws_id = "AKIA" + "QWER1234ZXCV5678"
    aws_pair = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "z9X8y7W6v5"
    assert len(aws_pair) == 40

    def _router(req: urllib.request.Request, timeout: float):
        if req.full_url == "https://api.openai.com/v1/models":
            err_fp = io.BytesIO(b'{"error":{"message":"Incorrect token"}}')
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, err_fp)
        if req.full_url == "https://slack.com/api/auth.test":
            return _MockHttpResponse(200, {"ok": False, "error": "invalid_auth"})
        if req.full_url == "https://sts.amazonaws.com/":
            auth_val = req.get_header("Authorization") or ""
            assert auth_val.startswith("AWS4-HMAC-SHA256 Credential=" + aws_id + "/")
            body_bytes = req.data or b""
            assert b"Action=GetCallerIdentity" in body_bytes
            xml_resp = (
                "<GetCallerIdentityResponse>"
                "<GetCallerIdentityResult>"
                "<Account>123456789012</Account>"
                "<Arn>arn:aws:iam::123456789012:user/ci-deployer</Arn>"
                "</GetCallerIdentityResult>"
                "</GetCallerIdentityResponse>"
            )
            return _MockHttpResponse(200, xml_resp, headers={"Content-Type": "text/xml"})
        raise AssertionError(f"Unexpected URL: {req.full_url}")

    mock_opener = _MockOpener(_router)
    eng = SecretValidatorEngine(platform_root=str(tmp_path))

    with patch.object(eng, "_build_http_opener", return_value=mock_opener):
        res_oai = eng.validate_secret_value(oai_tok, allow_live=True, force_refresh=True)
        res_slack = eng.validate_secret_value(slack_tok, allow_live=True, force_refresh=True)
        aws_ctx = f'AWS_ACCESS_KEY_ID="{aws_id}"\nAWS_PAIR="{aws_pair}"\n'
        res_aws_paired = eng.validate_secret_value(
            aws_id, context_text=aws_ctx, allow_live=True, force_refresh=True
        )
        calls_before_unpaired = len(mock_opener.calls)
        res_aws_unpaired = eng.validate_secret_value(
            aws_id, context_text=f'AWS_ID="{aws_id}"\n', allow_live=True, force_refresh=True
        )

    assert res_oai["secret_validation_status"] == "REVOKED_OR_INVALID"
    assert res_oai["secret_detector_id"] == "openai_key"
    assert oai_tok not in (res_oai.get("secret_validation_message") or "")

    assert res_slack["secret_validation_status"] == "REVOKED_OR_INVALID"
    assert res_slack["secret_detector_id"] == "slack_token"

    assert res_aws_paired["secret_validation_status"] == "VERIFIED_ACTIVE"
    assert res_aws_paired["secret_detector_id"] == "aws_iam"
    assert "123456789012" in (res_aws_paired.get("secret_verified_identity") or "")
    assert "ci-deployer" in (res_aws_paired.get("secret_verified_identity") or "")

    assert res_aws_unpaired["secret_validation_status"] == "OFFLINE_STRUCTURALLY_VALID"
    assert len(mock_opener.calls) == calls_before_unpaired


def test_placeholder_and_test_keys_make_zero_network_calls(tmp_path: Path):
    from engine.secret_validator_engine import SecretValidatorEngine

    stripe_test = "sk_test_" + "4eC39HqL" + "yjWDarjtT1zdp7dc"
    aws_example = "AKIA" + "IOSFODNN7" + "EXAMPLE"

    mock_opener = _MockOpener(lambda req, timeout: (_ for _ in ()).throw(AssertionError("Network must not be called")))
    eng = SecretValidatorEngine(platform_root=str(tmp_path))

    with patch.object(eng, "_build_http_opener", return_value=mock_opener):
        r1 = eng.validate_secret_value(stripe_test, allow_live=True, force_refresh=True)
        r2 = eng.validate_secret_value(aws_example, allow_live=True, force_refresh=True)
        r3 = eng.validate_secret_value("changeme_placeholder_123", key_name="APP_TOKEN", allow_live=True)

    assert len(mock_opener.calls) == 0
    assert r1["secret_validation_status"] == "TEST_OR_PLACEHOLDER"
    assert r1["secret_detector_id"] == "stripe_key"
    assert r2["secret_validation_status"] == "TEST_OR_PLACEHOLDER"
    assert r2["secret_detector_id"] == "aws_iam"
    assert r3["secret_validation_status"] == "TEST_OR_PLACEHOLDER"


def test_offline_deterministic_jwt_pem_and_database_uri(tmp_path: Path):
    from engine.secret_validator_engine import SecretValidatorEngine

    now_ts = int(time.time())
    unexpired_jwt = _build_jwt(now_ts + 86400, iss="https://sso.corp.example", sub="admin-user")
    expired_jwt = _build_jwt(now_ts - 86400, iss="https://sso.corp.example", sub="old-user")

    pem_hdr = "-----BEGIN RSA PRIVATE " + "KEY-----"
    pem_ftr = "-----END RSA PRIVATE " + "KEY-----"
    pem_body = base64.b64encode(b"0" * 96).decode("ascii")
    pem_block = f"{pem_hdr}\n{pem_body[:64]}\n{pem_body[64:]}\n{pem_ftr}"

    pg_uri = "postgres://admin:" + "S3cureP@ssw0rd99!" + "@db.internal:5432/prod"

    mock_opener = _MockOpener(lambda req, timeout: (_ for _ in ()).throw(AssertionError("No network expected")))
    eng = SecretValidatorEngine(platform_root=str(tmp_path))

    with patch.object(eng, "_build_http_opener", return_value=mock_opener):
        res_jwt_ok = eng.validate_secret_value(unexpired_jwt, allow_live=True)
        res_jwt_exp = eng.validate_secret_value(expired_jwt, allow_live=True)
        res_pem = eng.validate_secret_value(pem_block, allow_live=True)
        res_pg = eng.validate_secret_value(pg_uri, allow_live=True)

    assert len(mock_opener.calls) == 0

    assert res_jwt_ok["secret_detector_id"] == "jwt_bearer"
    assert res_jwt_ok["secret_validation_status"] == "OFFLINE_STRUCTURALLY_VALID"
    assert "admin-user" in (res_jwt_ok.get("secret_verified_identity") or res_jwt_ok.get("secret_validation_message") or "")

    assert res_jwt_exp["secret_detector_id"] == "jwt_bearer"
    assert res_jwt_exp["secret_validation_status"] == "REVOKED_OR_INVALID"
    assert "expired" in (res_jwt_exp.get("secret_validation_message") or "").lower()

    assert res_pem["secret_detector_id"] == "private_key_pem"
    assert res_pem["secret_validation_status"] == "OFFLINE_STRUCTURALLY_VALID"

    assert res_pg["secret_detector_id"] == "database_uri"
    assert res_pg["secret_validation_status"] == "OFFLINE_STRUCTURALLY_VALID"
    assert "db.internal" in (res_pg.get("secret_verified_identity") or res_pg.get("secret_validation_message") or "")


def test_offline_mode_caching_redirect_blocking_and_ssrf_guard(tmp_path: Path):
    from engine.secret_validator_engine import SecretValidatorEngine
    from models import SecretScannerConfigUpdate

    gh_tok = "ghp_" + ("K9m4" * 9)
    gem_tok = "AIza" + "SyB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R"
    assert len(gem_tok) == 39

    eng = SecretValidatorEngine(platform_root=str(tmp_path))
    updated_cfg = eng.update_config(SecretScannerConfigUpdate(live_verification_enabled=False))
    assert updated_cfg.live_verification_enabled is False

    cfg_file = tmp_path / ".alastor_vault" / "secret_scanner_config.json"
    assert cfg_file.is_file()

    # Reload engine from disk vault to verify persistence
    eng_reloaded = SecretValidatorEngine(platform_root=str(tmp_path))
    assert eng_reloaded.get_config().live_verification_enabled is False

    zero_opener = _MockOpener(lambda req, timeout: (_ for _ in ()).throw(AssertionError("Offline mode must not call network")))
    with patch.object(eng_reloaded, "_build_http_opener", return_value=zero_opener):
        off_gh = eng_reloaded.validate_secret_value(gh_tok)
        off_gem = eng_reloaded.validate_secret_value(gem_tok)

    assert len(zero_opener.calls) == 0
    assert off_gh["secret_validation_status"] == "OFFLINE_STRUCTURALLY_VALID"
    assert off_gem["secret_validation_status"] == "OFFLINE_STRUCTURALLY_VALID"

    # Switch back to Live Mode and verify SHA-256 cache + x-goog-api-key header (never query param)
    eng_reloaded.update_config(SecretScannerConfigUpdate(live_verification_enabled=True))

    def _live_gem_handler(req: urllib.request.Request, timeout: float):
        assert req.full_url == "https://generativelanguage.googleapis.com/v1beta/models"
        assert gem_tok not in req.full_url
        assert req.get_header("X-goog-api-key") == gem_tok
        return _MockHttpResponse(200, {"models": [{"name": "models/gemini-2.5-flash"}]})

    live_opener = _MockOpener(_live_gem_handler)
    with patch.object(eng_reloaded, "_build_http_opener", return_value=live_opener):
        first_live = eng_reloaded.validate_secret_value(gem_tok)
        second_cached = eng_reloaded.validate_secret_value(gem_tok)
        assert len(live_opener.calls) == 1
        assert first_live["secret_validation_status"] == "VERIFIED_ACTIVE"
        assert second_cached["secret_validation_status"] == "VERIFIED_ACTIVE"

        third_forced = eng_reloaded.validate_secret_value(gem_tok, force_refresh=True)
        assert len(live_opener.calls) == 2
        assert third_forced["secret_validation_status"] == "VERIFIED_ACTIVE"

    # 302 redirect response is blocked and surfaces VERIFICATION_ERROR
    def _redirect_handler(req: urllib.request.Request, timeout: float):
        from engine.secret_validator_engine import _NoRedirectHandler

        handler = _NoRedirectHandler()
        fp = io.BytesIO(b"")
        handler.redirect_request(req, fp, 302, "Found", {}, "https://evil.example.com/steal")

    redir_opener = _MockOpener(_redirect_handler)
    with patch.object(eng_reloaded, "_build_http_opener", return_value=redir_opener):
        redir_res = eng_reloaded.validate_secret_value(gh_tok, force_refresh=True)

    assert redir_res["secret_validation_status"] == "VERIFICATION_ERROR"
    assert "redirect" in (redir_res.get("secret_validation_message") or "").lower()

    # SSRF guard rejects unallowlisted hosts and plain http:// schemes
    with pytest.raises(ValueError):
        eng_reloaded._http_probe("https://evil.attacker.internal/user")
    with pytest.raises(ValueError):
        eng_reloaded._http_probe("http://api.github.com/user")


def test_git_commit_history_hunter_and_deduplication(tmp_path: Path):
    from engine.enterprise_manager import EnterpriseManager
    from engine.secret_validator_engine import SecretValidatorEngine
    from models import SecretScannerConfigUpdate

    repo_dir = tmp_path / "sample_git_repo"
    repo_dir.mkdir()

    git_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "dev@corp.local"], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Alice SecOps"], check=True, capture_output=True, env=git_env)

    gl_deleted_tok = "glpat-" + "Zz99Xx88Yy77Ww66Vv55"
    hf_active_tok = "hf_" + ("AbCdEfGhIjKlMnOpQr"[:17] * 2)
    assert len(hf_active_tok) == 37

    cfg_py = repo_dir / "config.py"
    cfg_py.write_text(
        f'GITLAB_DEPLOY_TOKEN = "{gl_deleted_tok}"\nHF_HUB_TOKEN = "{hf_active_tok}"\n',
        encoding="utf-8",
    )
    docs_dir = repo_dir / "docs"
    docs_dir.mkdir()
    (docs_dir / "guide.md").write_text(f"Example: `{gl_deleted_tok}`\n", encoding="utf-8")

    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Add initial tokens"], check=True, capture_output=True, env=git_env)

    # Second commit deletes GITLAB_DEPLOY_TOKEN from working tree while keeping HF_HUB_TOKEN
    cfg_py.write_text(f'HF_HUB_TOKEN = "{hf_active_tok}"\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "config.py"], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Remove gitlab token from working tree"], check=True, capture_output=True, env=git_env)

    eng = SecretValidatorEngine(platform_root=str(tmp_path))
    eng.update_config(SecretScannerConfigUpdate(live_verification_enabled=False, scan_git_history=True, max_git_commits=50))

    findings = eng.scan_and_validate_workspace(str(repo_dir), existing_findings=[])

    git_leaks = [f for f in findings if f.rule_id == "SECRET-GIT-HISTORY-LEAK"]
    assert len(git_leaks) == 1
    leak = git_leaks[0]
    assert leak.secret_source == "GIT_HISTORY"
    assert leak.secret_detector_id == "gitlab_pat"
    assert leak.secret_commit_sha and len(leak.secret_commit_sha) >= 7
    assert "Alice SecOps" in (leak.secret_commit_author or "")
    assert leak.secret_value_masked is not None
    assert "••••" in leak.secret_value_masked
    assert "Xx88Yy77" not in leak.secret_value_masked
    assert leak.secret_validation_status == "OFFLINE_STRUCTURALLY_VALID"

    # HF_HUB_TOKEN is still in working tree -> emitted once as WORKING_TREE (not duplicated as GIT_HISTORY)
    hf_findings = [f for f in findings if f.secret_detector_id == "huggingface_token"]
    assert len(hf_findings) == 1
    assert hf_findings[0].secret_source == "WORKING_TREE"
    assert hf_findings[0].secret_commit_sha is not None

    # Verify EnterpriseManager.enrich_findings preserves SECRET-GIT-HISTORY-LEAK and validation metadata
    em = EnterpriseManager.get_instance()
    enriched = em.enrich_findings(findings)
    enriched_git = [f for f in enriched if f.rule_id == "SECRET-GIT-HISTORY-LEAK"]
    assert len(enriched_git) == 1
    assert enriched_git[0].secret_source == "GIT_HISTORY"
    assert enriched_git[0].secret_commit_sha == leak.secret_commit_sha
    assert enriched_git[0].secret_detector_id == "gitlab_pat"
    assert enriched_git[0].secret_validation_status == "OFFLINE_STRUCTURALLY_VALID"


def test_fastapi_secret_routes_config_inventory_and_verify(tmp_path: Path):
    import main
    from engine.secret_validator_engine import SecretValidatorEngine
    from models import BestFixLocation, Finding

    iso_eng = SecretValidatorEngine(platform_root=str(tmp_path))
    sg_tok = "SG." + ("Qm9zX7" + "kLp2Wn8Vr4" + "Ty6Hu1") + "." + ("Kp3Mn7Qr9St" * 4)[:43]
    stripe_placeholder = "sk_test_" + "4eC39HqL" + "yjWDarjtT1zdp7dc"

    f_live = Finding(
        id="SEC-SG-1",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="HIGH",
        title="Exposed SendGrid Token",
        description="SendGrid credential in mailer.py",
        cwe_id="CWE-798",
        is_secret_finding=True,
        secret_key_name="SENDGRID_TOKEN",
        secret_value_raw=sg_tok,
        secret_value_masked="SG.A••••••••54_-",
        secret_validation_status="OFFLINE_STRUCTURALLY_VALID",
        secret_detector_id="sendgrid_key",
        secret_source="WORKING_TREE",
        path_nodes=[{"id": "n1", "label": "Assignment", "name": "SENDGRID_TOKEN", "code": "SENDGRID_TOKEN = '...'", "filepath": "mailer.py", "start_line": 4, "end_line": 4}],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id="n1", filepath="mailer.py", line=4, column=0,
            code_snippet="SENDGRID_TOKEN = '...'", explanation="Rotate token", recommended_fix="os.getenv('SENDGRID_TOKEN')"
        ),
    )
    f_test = Finding(
        id="SEC-ST-2",
        rule_id="SECRET-GIT-HISTORY-LEAK",
        severity="MEDIUM",
        title="Historical Stripe Test Token",
        description="Test token in git history",
        cwe_id="CWE-798",
        is_secret_finding=True,
        secret_key_name="STRIPE_KEY",
        secret_value_raw=stripe_placeholder,
        secret_value_masked="sk_t••••••••p7dc",
        secret_validation_status="TEST_OR_PLACEHOLDER",
        secret_detector_id="stripe_key",
        secret_source="GIT_HISTORY",
        secret_commit_sha="a1b2c3d4",
        secret_commit_author="Bob Dev",
        path_nodes=[{"id": "n2", "label": "Assignment", "name": "STRIPE_KEY", "code": "STRIPE_KEY = '...'", "filepath": "pay.py", "start_line": 9, "end_line": 9}],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id="n2", filepath="pay.py", line=9, column=0,
            code_snippet="STRIPE_KEY = '...'", explanation="Purge git history", recommended_fix="git filter-repo"
        ),
    )

    def _sg_opener_fn(req: urllib.request.Request, timeout: float):
        assert req.full_url == "https://api.sendgrid.com/v3/scopes"
        return _MockHttpResponse(200, {"scopes": ["mail.send", "alerts.read"]})

    mock_opener = _MockOpener(_sg_opener_fn)

    prev_cached = main._cached_findings
    prev_cached_time = main._cached_findings_time
    prev_scan_dir = main.current_scan_dir
    try:
        main.current_scan_dir = str(tmp_path)
        main._cached_findings = [f_live, f_test]
        main._cached_findings_time = time.time()

        with (
            patch.object(main, "secret_validator_engine", iso_eng),
            patch.object(iso_eng, "_build_http_opener", return_value=mock_opener),
            TestClient(main.app) as client,
        ):
            # 1. GET /api/secrets/config
            r_cfg = client.get("/api/secrets/config")
            assert r_cfg.status_code == 200
            cfg_json = r_cfg.json()
            assert cfg_json["live_verification_enabled"] is True
            assert cfg_json["scan_git_history"] is True
            assert cfg_json["max_git_commits"] == 50
            assert cfg_json["supported_detectors_count"] == 14

            # 2. POST /api/secrets/config (changing max_git_commits invalidates _cached_findings)
            r_upd = client.post(
                "/api/secrets/config",
                json={"live_verification_enabled": False, "max_git_commits": 25},
            )
            assert r_upd.status_code == 200
            upd_json = r_upd.json()
            assert upd_json["live_verification_enabled"] is False
            assert upd_json["max_git_commits"] == 25
            assert main._cached_findings is None

            # Re-seed synthetic in-memory cache for route inventory & live-verify assertions
            main._cached_findings = [f_live, f_test]
            main._cached_findings_time = time.time()

            # 3. GET /api/secrets/inventory
            r_inv = client.get("/api/secrets/inventory")
            assert r_inv.status_code == 200
            inv_json = r_inv.json()
            assert inv_json["total_secrets"] == 2
            assert inv_json["structurally_valid_count"] == 1
            assert inv_json["test_placeholder_count"] == 1
            assert inv_json["git_history_count"] == 1

            # 4. POST /api/secrets/verify with explicit allow_live_network=True
            r_ver = client.post(
                "/api/secrets/verify",
                json={"finding_ids": ["SEC-SG-1"], "force_refresh": True, "allow_live_network": True},
            )
            assert r_ver.status_code == 200
            ver_json = r_ver.json()
            assert ver_json["verified_active_count"] == 1
            sg_updated = next(s for s in ver_json["secrets"] if s["id"] == "SEC-SG-1")
            assert sg_updated["secret_validation_status"] == "VERIFIED_ACTIVE"
            assert sg_updated["severity"] == "CRITICAL"
            assert "mail.send" in (sg_updated.get("secret_verified_identity") or "")

            # Confirm main._cached_findings was updated in place
            cached_sg = next(f for f in (main._cached_findings or []) if f.id == "SEC-SG-1")
            assert cached_sg.secret_validation_status == "VERIFIED_ACTIVE"
            assert cached_sg.severity == "CRITICAL"
    finally:
        main._cached_findings = prev_cached
        main._cached_findings_time = prev_cached_time
        main.current_scan_dir = prev_scan_dir


def test_toggle_scan_git_history_invalidates_cached_findings_via_api(tmp_path: Path):
    import main
    from engine.secret_validator_engine import SecretValidatorEngine
    from models import SecretScannerConfigUpdate

    repo_dir = tmp_path / "git_toggle_repo"
    repo_dir.mkdir()

    git_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "secops@corp.local"], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Dana Auditor"], check=True, capture_output=True, env=git_env)

    gl_hist_tok = "glpat-" + "Mm11Nn22Bb33Vv44Cc55"
    hf_tree_tok = "hf_" + ("QrStUvWxYzAbCdEfG" * 2)
    assert len(hf_tree_tok) == 37

    settings_py = repo_dir / "settings.py"
    settings_py.write_text(
        f'GITLAB_TOKEN_VAL = "{gl_hist_tok}"\nHF_TOKEN_VAL = "{hf_tree_tok}"\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Initial commit with two tokens"], check=True, capture_output=True, env=git_env)

    # Remove GitLab token from working tree in second commit so it exists ONLY in .git history
    settings_py.write_text(f'HF_TOKEN_VAL = "{hf_tree_tok}"\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "settings.py"], check=True, capture_output=True, env=git_env)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Remove GitLab token from working tree"], check=True, capture_output=True, env=git_env)

    iso_eng = SecretValidatorEngine(platform_root=str(tmp_path))
    iso_eng.update_config(
        SecretScannerConfigUpdate(
            live_verification_enabled=False,
            scan_git_history=True,
            max_git_commits=50,
        )
    )

    prev_cached = main._cached_findings
    prev_cached_time = main._cached_findings_time
    prev_scan_dir = main.current_scan_dir
    prev_active_user = main.enterprise_mgr.active_user_id
    try:
        main.current_scan_dir = str(repo_dir)
        main._cached_findings = None
        main._cached_findings_time = 0.0
        main.enterprise_mgr.active_user_id = "usr-architect"

        with (
            patch.object(main, "secret_validator_engine", iso_eng),
            patch.object(main.RuleExecutor, "run_all_rules", return_value=[]),
            TestClient(main.app) as client,
        ):
            # 1. Initial GET /api/secrets/inventory & GET /api/findings include GIT_HISTORY
            inv_on = client.get("/api/secrets/inventory").json()
            findings_on = client.get("/api/findings").json()
            assert main._cached_findings is not None
            assert inv_on["git_history_count"] == 1
            assert any(s["secret_source"] == "GIT_HISTORY" for s in inv_on["secrets"])
            assert any(f.get("secret_source") == "GIT_HISTORY" for f in findings_on)
            assert any(s["secret_source"] == "WORKING_TREE" for s in inv_on["secrets"])

            # Updating only live_verification_enabled does NOT wipe _cached_findings
            r_live_only = client.post("/api/secrets/config", json={"live_verification_enabled": False})
            assert r_live_only.status_code == 200
            assert main._cached_findings is not None

            # 2. Toggle scan_git_history -> False WITHOUT calling POST /api/scan
            r_off = client.post("/api/secrets/config", json={"scan_git_history": False})
            assert r_off.status_code == 200
            assert r_off.json()["scan_git_history"] is False
            assert main._cached_findings is None

            inv_off = client.get("/api/secrets/inventory").json()
            findings_off = client.get("/api/findings").json()
            assert inv_off["git_history_count"] == 0
            assert not any(s["secret_source"] == "GIT_HISTORY" for s in inv_off["secrets"])
            assert not any(f.get("secret_source") == "GIT_HISTORY" for f in findings_off)
            assert any(s["secret_source"] == "WORKING_TREE" for s in inv_off["secrets"])

            # 3. Toggle scan_git_history -> True WITHOUT calling POST /api/scan
            r_reenable = client.post("/api/secrets/config", json={"scan_git_history": True})
            assert r_reenable.status_code == 200
            assert r_reenable.json()["scan_git_history"] is True
            assert main._cached_findings is None

            inv_back = client.get("/api/secrets/inventory").json()
            findings_back = client.get("/api/findings").json()
            assert inv_back["git_history_count"] == 1
            assert any(s["secret_source"] == "GIT_HISTORY" for s in inv_back["secrets"])
            assert any(f.get("secret_source") == "GIT_HISTORY" for f in findings_back)
    finally:
        main._cached_findings = prev_cached
        main._cached_findings_time = prev_cached_time
        main.current_scan_dir = prev_scan_dir
        main.enterprise_mgr.active_user_id = prev_active_user


def test_rbac_secret_value_raw_redaction_and_live_verify_preservation(tmp_path: Path):
    import main
    from engine.secret_validator_engine import SecretValidatorEngine
    from models import BestFixLocation, Finding

    iso_eng = SecretValidatorEngine(platform_root=str(tmp_path))
    sg_tok = "SG." + ("Zx8Cv6" + "Bn4Mq2Wp9" + "Lk7Jh3") + "." + ("Rt5Yu7Io9Pa" * 4)[:43]
    masked_display = f"{sg_tok[:4]}••••••••{sg_tok[-4:]}"

    f_secret = Finding(
        id="SEC-RBAC-SG-1",
        rule_id="RULE-8-HARDCODED-SECRET",
        severity="HIGH",
        title="Exposed SendGrid Credential",
        description="SendGrid token in notify.py",
        cwe_id="CWE-798",
        is_secret_finding=True,
        secret_key_name="NOTIFY_SG_CRED",
        secret_value_raw=sg_tok,
        secret_value_masked=masked_display,
        secret_validation_status="OFFLINE_STRUCTURALLY_VALID",
        secret_detector_id="sendgrid_key",
        secret_source="WORKING_TREE",
        path_nodes=[
            {
                "id": "n-rbac-1",
                "label": "Assignment",
                "name": "NOTIFY_SG_CRED",
                "code": "NOTIFY_SG_CRED = '...'",
                "filepath": "notify.py",
                "start_line": 7,
                "end_line": 7,
            }
        ],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id="n-rbac-1",
            filepath="notify.py",
            line=7,
            column=0,
            code_snippet="NOTIFY_SG_CRED = '...'",
            explanation="Move credential to vault",
            recommended_fix="os.getenv('NOTIFY_SG_CRED')",
        ),
    )

    def _sg_live_fn(req: urllib.request.Request, timeout: float):
        assert req.full_url == "https://api.sendgrid.com/v3/scopes"
        assert req.get_header("Authorization") == f"Bearer {sg_tok}"
        return _MockHttpResponse(200, {"scopes": ["mail.send"]})

    mock_opener = _MockOpener(_sg_live_fn)

    prev_cached = main._cached_findings
    prev_cached_time = main._cached_findings_time
    prev_scan_dir = main.current_scan_dir
    prev_active_user = main.enterprise_mgr.active_user_id
    prev_active_account = main.enterprise_mgr.active_account_id
    prev_active_preset = main.enterprise_mgr.active_preset_id
    prev_users = [u.model_copy(deep=True) for u in main.enterprise_mgr.user_profiles]
    prev_audit_log = list(main.enterprise_mgr.account_audit_log)
    try:
        main.current_scan_dir = str(tmp_path)
        main._cached_findings = [f_secret]
        main._cached_findings_time = time.time()

        with (
            patch.object(main, "secret_validator_engine", iso_eng),
            patch.object(iso_eng, "_build_http_opener", return_value=mock_opener),
            patch.object(main.enterprise_mgr, "_save_persisted_state", return_value=None),
            TestClient(main.app) as client,
        ):
            # 1. Authorized admin/architect session (can_reveal_secrets == True)
            r_sw_admin = client.post("/api/accounts/switch", json={"user_id": "usr-architect"})
            assert r_sw_admin.status_code == 200
            assert main.enterprise_mgr.active_user_can_reveal_secrets() is True

            admin_findings = client.get("/api/findings").json()
            admin_inv = client.get("/api/secrets/inventory").json()
            f_admin = next(f for f in admin_findings if f["id"] == "SEC-RBAC-SG-1")
            s_admin = next(s for s in admin_inv["secrets"] if s["id"] == "SEC-RBAC-SG-1")
            assert f_admin["secret_value_raw"] == sg_tok
            assert s_admin["secret_value_raw"] == sg_tok

            # 2. Switch to restricted developer profile (can_reveal_secrets == False)
            r_sw_dev = client.post("/api/accounts/switch", json={"user_id": "usr-developer"})
            assert r_sw_dev.status_code == 200
            assert main.enterprise_mgr.active_user_can_reveal_secrets() is False

            dev_findings = client.get("/api/findings").json()
            dev_inv = client.get("/api/secrets/inventory").json()
            f_dev = next(f for f in dev_findings if f["id"] == "SEC-RBAC-SG-1")
            s_dev = next(s for s in dev_inv["secrets"] if s["id"] == "SEC-RBAC-SG-1")
            assert f_dev["secret_value_raw"] is None
            assert f_dev["secret_value_masked"] == masked_display
            assert s_dev["secret_value_raw"] is None
            assert s_dev["secret_value_masked"] == masked_display

            # Live verification STILL works using in-memory raw secret while redacting HTTP output
            r_ver_dev = client.post(
                "/api/secrets/verify",
                json={"finding_ids": ["SEC-RBAC-SG-1"], "force_refresh": True, "allow_live_network": True},
            )
            assert r_ver_dev.status_code == 200
            ver_dev_json = r_ver_dev.json()
            assert len(mock_opener.calls) == 1
            s_ver_dev = next(s for s in ver_dev_json["secrets"] if s["id"] == "SEC-RBAC-SG-1")
            assert s_ver_dev["secret_validation_status"] == "VERIFIED_ACTIVE"
            assert s_ver_dev["severity"] == "CRITICAL"
            assert s_ver_dev["secret_value_raw"] is None
            assert s_ver_dev["secret_value_masked"] == masked_display

            # In-memory _cached_findings was NEVER mutated to None
            assert main._cached_findings is not None
            assert main._cached_findings[0].secret_value_raw == sg_tok

            # 3. Switch back to authorized architect profile -> raw value immediately restored
            r_sw_back = client.post("/api/accounts/switch", json={"user_id": "usr-architect"})
            assert r_sw_back.status_code == 200
            assert main.enterprise_mgr.active_user_can_reveal_secrets() is True

            restored_findings = client.get("/api/findings").json()
            restored_inv = client.get("/api/secrets/inventory").json()
            f_restored = next(f for f in restored_findings if f["id"] == "SEC-RBAC-SG-1")
            s_restored = next(s for s in restored_inv["secrets"] if s["id"] == "SEC-RBAC-SG-1")
            assert f_restored["secret_value_raw"] == sg_tok
            assert f_restored["secret_validation_status"] == "VERIFIED_ACTIVE"
            assert s_restored["secret_value_raw"] == sg_tok
            assert s_restored["secret_validation_status"] == "VERIFIED_ACTIVE"
    finally:
        main._cached_findings = prev_cached
        main._cached_findings_time = prev_cached_time
        main.current_scan_dir = prev_scan_dir
        main.enterprise_mgr.active_user_id = prev_active_user
        main.enterprise_mgr.active_account_id = prev_active_account
        main.enterprise_mgr.active_preset_id = prev_active_preset
        main.enterprise_mgr.user_profiles = prev_users
        main.enterprise_mgr.account_audit_log = prev_audit_log
