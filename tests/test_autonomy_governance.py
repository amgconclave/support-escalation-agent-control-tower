from pathlib import Path


def _analyze(client, headers, payload):
    ticket = client.post("/tickets/ingest", headers=headers, json=payload).json()
    run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=headers).json()
    return ticket, run


def test_autonomy_audit_reports_loop_tool_hitl_and_cost_controls(client, auth_headers):
    _ticket, run = _analyze(
        client,
        auth_headers,
        {
            "subject": "Production webhook 500 regression",
            "body": "Webhook deliveries return 500 errors in production and the customer reports SLA risk.",
            "customer": "Atlas Logistics",
            "priority": "high",
            "customer_tier": "enterprise",
            "tags": ["webhook", "api", "regression", "sla"],
        },
    )

    response = client.get("/governance/autonomy-audit", headers=auth_headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["title"] == "Autonomy Governance Audit"
    assert audit["local_mock_only"] is True
    assert audit["readiness_status"] in {"ready", "review", "blocked"}
    assert audit["governance_score"] >= 0
    assert {"autonomous loop controls", "tool governance"} <= set(audit["repo_radar_patterns"])
    assert {item["control_id"] for item in audit["control_checks"]} >= {
        "bounded_workflow_nodes",
        "trusted_tool_allowlist",
        "human_approval_before_dispatch",
        "cost_token_observability",
    }
    row = next(item for item in audit["run_governance"] if item["run_id"] == run["run_id"])
    assert row["loop_budget"]["status"] == "pass"
    assert row["tool_trust"]["status"] == "pass"
    assert row["approval_status"] == "pending"
    assert row["trace_id"] == run["trace_id"]
    assert audit["owner_action_plan"]
    assert "GET /governance/autonomy-audit" in audit["endpoint_list"]


def test_autonomy_pack_exports_markdown_json_and_reviewer_artifacts(client, auth_headers):
    _analyze(
        client,
        auth_headers,
        {
            "subject": "Ambiguous issue needs careful review",
            "body": "Something is odd ???",
            "customer": "Greyline Media",
            "priority": "low",
            "customer_tier": "standard",
            "tags": [],
        },
    )

    response = client.post("/governance/autonomy-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert "autonomy_governance_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Autonomy Governance and Tool Trust Pack"
    assert pack["reviewer_artifacts"]["export_endpoint"] == "POST /governance/autonomy-pack"
    assert pack["decision_table"]
    assert "## Control Checks" in exported["markdown"]
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "tool trust" in saved.lower()
    assert "loop budget" in saved.lower()


def test_autonomy_governance_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/governance/autonomy-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(item["label"] == "Autonomy Governance" and item["present"] for item in smoke["expected_views"])
    assert any(
        item["endpoint"] == "GET /governance/autonomy-audit"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /governance/autonomy-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "GET /governance/autonomy-audit" in {item["endpoint"] for item in contract["endpoint_inventory"]}
    assert any(
        item["producer"] == "POST /governance/autonomy-pack"
        and item["artifact_directory"] == "data/autonomy_governance_packs"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/autonomy_governance_packs" for item in inventory["artifacts"])
