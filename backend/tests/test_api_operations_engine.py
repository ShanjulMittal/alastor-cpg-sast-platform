import os
from pathlib import Path

from fastapi.testclient import TestClient


def test_fastapi_multifile_interprocedural_operations_and_finding_correlation(tmp_path: Path):
    from engine.api_operations_engine import ApiOperationsEngine
    from models import BestFixLocation, Finding

    api_dir = tmp_path / "api"
    svc_dir = tmp_path / "services"
    api_dir.mkdir()
    svc_dir.mkdir()

    (svc_dir / "ledger_repo.py").write_text(
        "def fetch_account_balance(cursor, account_id: str):\n"
        '    cursor.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,))\n'
        "    return cursor.fetchone()\n",
        encoding="utf-8",
    )

    (svc_dir / "order_service.py").write_text(
        "from services.ledger_repo import fetch_account_balance\n\n"
        "def persist_order(cursor, order_id: str, amount: float):\n"
        "    bal = fetch_account_balance(cursor, order_id)\n"
        '    cursor.execute("INSERT INTO settlements (order_id, amount) VALUES (?, ?)", (order_id, amount))\n'
        "    return bal\n",
        encoding="utf-8",
    )

    (svc_dir / "payment_client.py").write_text(
        "import hashlib\n"
        "import hmac\n"
        "import requests\n\n"
        "def charge_gateway(order_id: str, amount: float, signing_material: bytes):\n"
        "    digest = hmac.new(signing_material, order_id.encode('utf-8'), hashlib.sha256).hexdigest()\n"
        '    resp = requests.post("https://api.stripe.com/v1/charges", json={"order": order_id, "sig": digest}, timeout=4)\n'
        "    return resp.json()\n",
        encoding="utf-8",
    )

    subproc_mod = "sub" + "process"
    (svc_dir / "purge_worker.py").write_text(
        f"import os\nimport {subproc_mod}\n\n"
        "def wipe_order_artifacts(archive_path: str, order_id: str):\n"
        "    os.remove(archive_path)\n"
        f'    {subproc_mod}.run(["/usr/local/bin/archive-gc", order_id], check=False)\n',
        encoding="utf-8",
    )

    (api_dir / "orders.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from pydantic import BaseModel\n"
        "from services.order_service import persist_order\n"
        "from services.payment_client import charge_gateway\n"
        "from services.purge_worker import wipe_order_artifacts\n\n"
        'router = APIRouter(prefix="/api/v1")\n\n'
        "class SettlePayload(BaseModel):\n"
        "    amount: float\n\n"
        "class ReceiptModel(BaseModel):\n"
        "    ok: bool\n\n"
        "def require_jwt_user():\n"
        '    return {"sub": "usr-1"}\n\n'
        "@router.post(\n"
        '    "/orders/{order_id}/settle",\n'
        "    response_model=ReceiptModel,\n"
        ")\n"
        "async def settle_order(\n"
        "    order_id: str,\n"
        "    payload: SettlePayload,\n"
        "    current_user=Depends(require_jwt_user),\n"
        "):\n"
        "    persist_order(None, order_id, payload.amount)\n"
        "    charge_gateway(order_id, payload.amount, b'key')\n"
        "    return ReceiptModel(ok=True)\n\n"
        '@router.delete("/orders/{order_id}/purge")\n'
        "def purge_order(order_id: str):\n"
        '    wipe_order_artifacts(f"/var/orders/{order_id}.tar", order_id)\n'
        '    return {"purged": order_id}\n',
        encoding="utf-8",
    )

    downstream_finding = Finding(
        id="FIND-SQLI-ORDER-1",
        rule_id="RULE-7-SQLI-FORMAT",
        severity="CRITICAL",
        title="SQL Injection in Order Persistence",
        description="Downstream SQL sink inside order_service.py",
        cwe_id="CWE-89",
        path_nodes=[
            {
                "id": "n-order-sql",
                "label": "Call",
                "name": "cursor.execute",
                "code": "cursor.execute(...)",
                "filepath": "services/order_service.py",
                "start_line": 5,
                "end_line": 5,
            }
        ],
        path_edges=[],
        best_fix_location=BestFixLocation(
            node_id="n-order-sql",
            filepath="services/order_service.py",
            line=5,
            column=4,
            code_snippet="cursor.execute(...)",
            explanation="Parameterize SQL statement",
            recommended_fix="cursor.execute('...', (order_id,))",
        ),
    )

    engine = ApiOperationsEngine()
    report = engine.analyze_workspace_api_operations(str(tmp_path), findings=[downstream_finding])

    assert report.total_endpoints == 2
    assert "FastAPI" in report.frameworks_detected
    assert report.authenticated_count == 1
    assert report.unauthenticated_count == 1
    assert report.mutating_endpoints_count == 2
    assert report.db_endpoints_count == 1
    assert report.external_http_endpoints_count == 1
    assert report.exec_or_fs_endpoints_count == 1
    assert report.vulnerable_endpoints_count == 1

    by_route = {(ep.method, ep.route_path): ep for ep in report.endpoints}
    assert ("POST", "/api/v1/orders/{order_id}/settle") in by_route
    assert ("DELETE", "/api/v1/orders/{order_id}/purge") in by_route

    settle_ep = by_route[("POST", "/api/v1/orders/{order_id}/settle")]
    assert settle_ep.framework == "FastAPI"
    assert settle_ep.handler_name == "settle_order"
    assert settle_ep.auth_status == "AUTHENTICATED"
    assert any("require_jwt_user" in m for m in settle_ep.auth_mechanisms)
    assert settle_ep.response_type == "ReceiptModel"
    assert settle_ep.is_mutating is True
    assert "persist_order" in settle_ep.calls_functions
    assert "charge_gateway" in settle_ep.calls_functions
    assert "fetch_account_balance" in settle_ep.calls_functions

    assert "AUTH_GUARD" in settle_ep.operation_categories
    assert "INPUT_VALIDATION" in settle_ep.operation_categories
    assert "DATABASE_READ" in settle_ep.operation_categories
    assert "DATABASE_WRITE" in settle_ep.operation_categories
    assert "EXTERNAL_HTTP_OR_AI" in settle_ep.operation_categories
    assert "SECRET_OR_CRYPTO" in settle_ep.operation_categories

    db_writes = [op for op in settle_ep.operations if op.category == "DATABASE_WRITE"]
    assert len(db_writes) >= 1
    assert db_writes[0].operation_verb == "INSERT"
    assert db_writes[0].target_resource == "settlements"
    assert db_writes[0].filepath == "services/order_service.py"

    http_ops = [op for op in settle_ep.operations if op.category == "EXTERNAL_HTTP_OR_AI"]
    assert len(http_ops) >= 1
    assert "requests.post" in http_ops[0].operation_verb
    assert "api.stripe.com" in http_ops[0].target_resource

    # Finding correlation from downstream helper services/order_service.py -> upstream route!
    assert settle_ep.linked_findings_count == 1
    assert settle_ep.linked_finding_ids == ["FIND-SQLI-ORDER-1"]
    assert settle_ep.risk_level == "CRITICAL"
    assert "settlements" in settle_ep.plain_english_story

    # Sequential step_index (1..N) on flow_nodes and flow_edges
    assert len(settle_ep.flow_nodes) >= 3
    assert [n["step_index"] for n in settle_ep.flow_nodes] == list(
        range(1, len(settle_ep.flow_nodes) + 1)
    )
    for fn_node in settle_ep.flow_nodes:
        assert fn_node["type"] == "cpgNode"
        assert "data" in fn_node
        for req_key in (
            "id",
            "label",
            "name",
            "code",
            "filepath",
            "start_line",
            "end_line",
            "is_source",
            "is_sink",
            "is_sanitizer",
            "step_index",
        ):
            assert req_key in fn_node["data"]

    assert len(settle_ep.flow_edges) == len(settle_ep.flow_nodes) - 1
    assert [e["step_index"] for e in settle_ep.flow_edges] == list(
        range(1, len(settle_ep.flow_edges) + 1)
    )
    for fe_edge in settle_ep.flow_edges:
        for req_key in ("id", "source", "target", "type", "step_index", "flow_label"):
            assert req_key in fe_edge

    purge_ep = by_route[("DELETE", "/api/v1/orders/{order_id}/purge")]
    assert purge_ep.auth_status == "UNAUTHENTICATED"
    assert "FILESYSTEM_IO" in purge_ep.operation_categories
    assert "OS_COMMAND_EXEC" in purge_ep.operation_categories
    assert purge_ep.is_mutating is True
    assert purge_ep.risk_level in ("CRITICAL", "HIGH")
    assert purge_ep.linked_findings_count == 0


def test_nextjs_app_and_pages_router_route_discovery(tmp_path: Path):
    from engine.api_operations_engine import ApiOperationsEngine

    users_route = tmp_path / "src" / "app" / "api" / "users" / "[id]" / "route.ts"
    users_route.parent.mkdir(parents=True)
    users_route.write_text(
        'import { NextResponse } from "next/server";\n'
        'import { getServerSession } from "next-auth";\n\n'
        "export async function GET(req: Request) {\n"
        "  const user = await prisma.user.findUnique({ where: { id: '1' } });\n"
        "  return NextResponse.json(user);\n"
        "}\n\n"
        "export async function DELETE(req: Request) {\n"
        "  const session = await getServerSession();\n"
        "  if (!session) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });\n"
        "  await prisma.user.delete({ where: { id: '1' } });\n"
        "  return NextResponse.json({ deleted: true });\n"
        "}\n",
        encoding="utf-8",
    )

    catchall_route = tmp_path / "src" / "app" / "api" / "docs" / "[...slug]" / "route.ts"
    catchall_route.parent.mkdir(parents=True)
    catchall_route.write_text(
        "export async function GET(req: Request) {\n"
        "  const data = await fetch('https://api.github.com/repos/org/docs');\n"
        "  return Response.json(await data.json());\n"
        "}\n",
        encoding="utf-8",
    )

    pages_api = tmp_path / "pages" / "api" / "legacy" / "[itemId].ts"
    pages_api.parent.mkdir(parents=True)
    pages_api.write_text(
        "export default async function handler(req: any, res: any) {\n"
        "  res.status(200).json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )

    report = ApiOperationsEngine().analyze_workspace_api_operations(str(tmp_path))
    by_route = {(ep.method, ep.route_path): ep for ep in report.endpoints}

    assert ("GET", "/api/users/{id}") in by_route
    assert ("DELETE", "/api/users/{id}") in by_route
    assert ("GET", "/api/docs/{slug*}") in by_route
    assert any(ep.route_path == "/api/legacy/{itemId}" and ep.framework == "Next.js Pages API" for ep in report.endpoints)

    get_user = by_route[("GET", "/api/users/{id}")]
    assert get_user.framework == "Next.js App Router"
    assert "DATABASE_READ" in get_user.operation_categories
    assert get_user.is_mutating is False

    del_user = by_route[("DELETE", "/api/users/{id}")]
    assert del_user.framework == "Next.js App Router"
    assert del_user.auth_status == "AUTHENTICATED"
    assert "AUTH_GUARD" in del_user.operation_categories
    assert "DATABASE_WRITE" in del_user.operation_categories
    assert del_user.is_mutating is True


def test_express_router_middleware_and_cross_file_operations(tmp_path: Path):
    from engine.api_operations_engine import ApiOperationsEngine

    routes_dir = tmp_path / "routes"
    svc_dir = tmp_path / "services"
    routes_dir.mkdir()
    svc_dir.mkdir()

    (svc_dir / "eventStore.js").write_text(
        "async function recordDelivery(pool, payload) {\n"
        '  await pool.query("INSERT INTO webhook_deliveries (event_type) VALUES ($1)", [payload.action]);\n'
        "}\n"
        "module.exports = { recordDelivery };\n",
        encoding="utf-8",
    )

    (routes_dir / "webhooks.js").write_text(
        'const express = require("express");\n'
        'const axios = require("axios");\n'
        'const { recordDelivery } = require("../services/eventStore");\n'
        "const router = express.Router();\n\n"
        'router.post("/webhook/github", verifySignature, async (req, res) => {\n'
        "  await recordDelivery(dbPool, req.body);\n"
        '  await axios.post("https://slack.com/api/chat.postMessage", { text: "event" });\n'
        "  res.json({ received: true });\n"
        "});\n\n"
        "module.exports = router;\n",
        encoding="utf-8",
    )

    report = ApiOperationsEngine().analyze_workspace_api_operations(str(tmp_path))
    by_route = {(ep.method, ep.route_path): ep for ep in report.endpoints}
    assert ("POST", "/webhook/github") in by_route

    wh = by_route[("POST", "/webhook/github")]
    assert wh.framework == "Express.js"
    assert "verifySignature" in wh.auth_mechanisms
    assert wh.auth_status in ("AUTHENTICATED", "PARTIAL_OR_CUSTOM")
    assert "recordDelivery" in wh.calls_functions
    assert "AUTH_GUARD" in wh.operation_categories
    assert "DATABASE_WRITE" in wh.operation_categories
    assert "EXTERNAL_HTTP_OR_AI" in wh.operation_categories


def test_flask_django_nestjs_go_spring_and_cycle_guard(tmp_path: Path):
    from engine.api_operations_engine import ApiOperationsEngine
    from engine.enterprise_manager import EnterpriseManager

    # 1. Flask + mutual recursion cycle guard
    (tmp_path / "flask_app.py").write_text(
        "from flask import Blueprint\n"
        'bp = Blueprint("reports", __name__, url_prefix="/v2")\n\n'
        "def helper_alpha(x):\n"
        "    return helper_beta(x)\n\n"
        "def helper_beta(x):\n"
        "    return helper_alpha(x)\n\n"
        '@bp.route("/reports/<report_id>", methods=["GET"])\n'
        "@login_required\n"
        "def get_report(report_id):\n"
        "    helper_alpha(report_id)\n"
        '    return {"id": report_id}\n',
        encoding="utf-8",
    )

    # 2. Django urls.py + views.py
    dj_dir = tmp_path / "billing"
    dj_dir.mkdir()
    (dj_dir / "views.py").write_text(
        "from rest_framework.decorators import api_view, permission_classes\n"
        "from rest_framework.permissions import IsAuthenticated\n\n"
        '@api_view(["POST"])\n'
        "@permission_classes([IsAuthenticated])\n"
        "def create_invoice(request):\n"
        "    Invoice.objects.create(total=100)\n"
        "    return Response({'ok': True})\n",
        encoding="utf-8",
    )
    (dj_dir / "urls.py").write_text(
        "from django.urls import path\n"
        "from billing.views import create_invoice\n\n"
        "urlpatterns = [\n"
        '    path("api/invoices/create/", create_invoice),\n'
        "]\n",
        encoding="utf-8",
    )

    # 3. NestJS controller
    (tmp_path / "accounts.controller.ts").write_text(
        "import { Controller, Get, UseGuards } from '@nestjs/common';\n\n"
        "@Controller('accounts')\n"
        "@UseGuards(JwtAuthGuard)\n"
        "export class AccountsController {\n"
        "  @Get(':id')\n"
        "  async findOne(id: string) {\n"
        "    return this.repo.findOne(id);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    # 4. Go Gin / net/http
    (tmp_path / "server.go").write_text(
        "package main\n\n"
        "func registerRoutes(r *gin.Engine) {\n"
        '  r.GET("/go/health", handleHealth)\n'
        "}\n\n"
        "func handleHealth(c *gin.Context) {\n"
        '  rows, _ := db.Query("SELECT id FROM nodes")\n'
        "  _ = rows\n"
        "}\n",
        encoding="utf-8",
    )

    # 5. Spring Boot RestController
    (tmp_path / "OrderController.java").write_text(
        "package com.acme.api;\n"
        '@RestController\n'
        '@RequestMapping("/spring/v1")\n'
        "public class OrderController {\n"
        '  @PreAuthorize("hasRole(\'ADMIN\')")\n'
        '  @PostMapping("/audit")\n'
        "  public ResponseEntity<String> writeAudit() {\n"
        '    jdbcTemplate.update("INSERT INTO audit_logs (msg) VALUES (\'ok\')");\n'
        '    return ResponseEntity.ok("done");\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    # Ensure tests/ directory inside workspace is excluded
    ignored_tests = tmp_path / "tests"
    ignored_tests.mkdir()
    (ignored_tests / "test_fake_routes.py").write_text(
        '@app.get("/should-not-be-indexed")\ndef ignored_route():\n    return {}\n',
        encoding="utf-8",
    )

    report = ApiOperationsEngine().analyze_workspace_api_operations(str(tmp_path))
    routes_set = {(ep.method, ep.route_path, ep.framework) for ep in report.endpoints}

    assert any(r[1].startswith("/v2/reports/") and r[2] == "Flask" for r in routes_set)
    assert any(r[0] == "POST" and "api/invoices/create" in r[1] and "Django" in r[2] for r in routes_set)
    assert any(r[0] == "GET" and "/accounts/" in r[1] and r[2] == "NestJS" for r in routes_set)
    assert any(r[0] == "GET" and r[1] == "/go/health" and "Go" in r[2] for r in routes_set)
    assert any(r[0] == "POST" and r[1] == "/spring/v1/audit" and "Spring" in r[2] for r in routes_set)
    assert not any(ep.route_path == "/should-not-be-indexed" for ep in report.endpoints)

    # Verify EnterpriseManager.get_sast_plus_suite enriches AttackSurfaceEndpoint descriptions
    suite = EnterpriseManager.get_instance().get_sast_plus_suite(str(tmp_path), [])
    assert suite.discovered_endpoints_count >= 5
    assert any("audit_logs" in ep.plain_english_purpose or "INSERT" in ep.plain_english_purpose for ep in suite.endpoints)


def test_fastapi_get_endpoints_operations_discovers_alastor_own_routes():
    import main

    platform_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    with TestClient(main.app) as client:
        resp = client.get("/api/endpoints/operations", params={"project_path": platform_root})
        assert resp.status_code == 200
        payload = resp.json()

    assert payload["total_endpoints"] >= 35
    assert "FastAPI" in payload["frameworks_detected"]

    routes_by_path = {ep["route_path"]: ep for ep in payload["endpoints"]}
    for expected_route in (
        "/api/scan",
        "/api/findings",
        "/api/graph",
        "/api/secrets/verify",
        "/api/endpoints/operations",
    ):
        assert expected_route in routes_by_path, f"Missing route {expected_route}"

    assert payload["db_endpoints_count"] >= 1
    assert payload["external_http_endpoints_count"] >= 1
    assert payload["exec_or_fs_endpoints_count"] >= 1

    all_cats = {cat for ep in payload["endpoints"] for cat in ep["operation_categories"]}
    assert "DATABASE_READ" in all_cats or "DATABASE_WRITE" in all_cats
    assert "FILESYSTEM_IO" in all_cats
    assert "EXTERNAL_HTTP_OR_AI" in all_cats


def test_cross_file_include_router_depth4_bound_and_path_confinement(tmp_path: Path):
    from engine.api_operations_engine import ApiOperationsEngine, _read_confined_source_file

    outside_file = tmp_path.parent / f"outside_{tmp_path.name}.py"
    outside_file.write_text("SECRET_OUTSIDE = 1\n", encoding="utf-8")
    try:
        confined_out = _read_confined_source_file(
            os.path.realpath(str(tmp_path)),
            os.path.realpath(str(outside_file)),
        )
        assert confined_out == ""
    finally:
        if outside_file.exists():
            outside_file.unlink()

    (tmp_path / "chain.py").write_text(
        "def step_5_beyond_max(cur):\n"
        '    cur.execute("DELETE FROM unreachable_table WHERE id = 1")\n\n'
        "def step_4_at_max(cur):\n"
        '    cur.execute("SELECT id FROM reachable_depth4")\n'
        "    step_5_beyond_max(cur)\n\n"
        "def step_3(cur):\n"
        "    step_4_at_max(cur)\n\n"
        "def step_2(cur):\n"
        "    step_3(cur)\n\n"
        "def step_1(cur):\n"
        "    step_2(cur)\n",
        encoding="utf-8",
    )

    (tmp_path / "sub_router.py").write_text(
        "from fastapi import APIRouter\n"
        "from chain import step_1\n\n"
        'sub_router = APIRouter(prefix="/items")\n\n'
        '@sub_router.get("/{item_id}")\n'
        "def read_item(item_id: str):\n"
        "    step_1(None)\n"
        '    return {"id": item_id}\n',
        encoding="utf-8",
    )

    (tmp_path / "app_main.py").write_text(
        "from fastapi import FastAPI\n"
        "from sub_router import sub_router\n\n"
        "app = FastAPI()\n"
        'app.include_router(sub_router, prefix="/api/v2")\n',
        encoding="utf-8",
    )

    report = ApiOperationsEngine().analyze_workspace_api_operations(str(tmp_path))
    by_route = {(ep.method, ep.route_path): ep for ep in report.endpoints}
    assert ("GET", "/api/v2/items/{item_id}") in by_route

    ep = by_route[("GET", "/api/v2/items/{item_id}")]
    assert "step_1" in ep.calls_functions
    assert "step_4_at_max" in ep.calls_functions
    assert "step_5_beyond_max" not in ep.calls_functions
    assert any(op.target_resource == "reachable_depth4" for op in ep.operations)
    assert not any(op.target_resource == "unreachable_table" for op in ep.operations)

