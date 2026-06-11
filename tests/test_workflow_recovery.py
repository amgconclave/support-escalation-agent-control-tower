from pathlib import Path


def _analyze(client, headers):
    ticket = client.post(
        "/tickets/ingest",
        headers=headers,
        json={
            "subject": "Enterprise SSO outage needs durable recovery",
            "body": "SAML SSO is down in production and SLA breach risk is high.",
            "customer": "Northstar Health",
            "priority": "urgent",
            "customer_tier": "enterprise",
            "tags": ["auth", "sso", "outage"],
        },
    ).json()
    run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=headers).json()
    return ticket, run


def test_workflow_persists_node_checkpoints_for_resume(client, auth_headers):
    _ticket, run = _analyze(client, auth_headers)
    state = run["state"]

    assert run["status"] == "awaiting_approval"
    assert state["durability"]["checkpoint_count"] == len(state["node_history"])
    assert state["durability"]["resume_token"].startswith(f"{run['run_id']}:chk_")
    assert [item["node"] for item in state["checkpoints"]] == state["node_history"]
    assert state["checkpoints"][-1]["node"] == "finalizer"
    assert state["checkpoints"][-1]["status"] == "completed"
    assert state["approval_id"].startswith("apr_")


def test_workflow_durability_audit_reports_resume_controls(client, auth_headers):
    _ticket, run = _analyze(client, auth_headers)

    response = client.get("/workflows/durability-audit", headers=auth_headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["title"] == "Durable Workflow Recovery Audit"
    assert audit["local_mock_only"] is True
    assert audit["readiness_status"] in {"ready", "review", "blocked"}
    assert audit["durability_score"] >= 0
    assert {"durable workflows", "checkpointing", "human-in-the-loop"} <= set(
        audit["repo_radar_patterns"]
    )
    assert {item["control_id"] for item in audit["control_checks"]} >= {
        "node_checkpoint_persistence",
        "hitl_resume_ready",
        "dispatch_boundary_safe",
        "resume_token_available",
    }
    row = next(item for item in audit["run_recovery"] if item["run_id"] == run["run_id"])
    assert row["checkpoint_count"] == row["expected_checkpoint_count"]
    assert row["resume_status"] == "resume_ready_human_approval"
    assert row["resume_token"].startswith(f"{run['run_id']}:chk_")
    assert row["outbox_dispatch_safe"] is True
    assert not row["missing_checkpoint_nodes"]
    assert any(item["run_id"] == run["run_id"] for item in audit["operator_recovery_queue"])
    assert "GET /workflows/durability-audit" in audit["endpoint_list"]


def test_workflow_durability_pack_exports_markdown_json_and_reviewer_artifacts(
    client,
    auth_headers,
):
    _analyze(client, auth_headers)

    response = client.post("/workflows/durability-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert "workflow_recovery_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Durable Workflow Recovery Pack"
    assert pack["reviewer_artifacts"]["audit_endpoint"] == "GET /workflows/durability-audit"
    assert pack["recovery_decision_table"]
    assert "## Operator Recovery Queue" in exported["markdown"]
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "resume token" in saved.lower()
    assert "checkpoint" in saved.lower()


def test_workflow_durability_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/workflows/durability-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(item["label"] == "Durable Workflows" and item["present"] for item in smoke["expected_views"])
    assert any(
        item["endpoint"] == "GET /workflows/durability-audit"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /workflows/durability-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "GET /workflows/durability-audit" in {
        item["endpoint"] for item in contract["endpoint_inventory"]
    }
    assert any(
        item["producer"] == "POST /workflows/durability-pack"
        and item["artifact_directory"] == "data/workflow_recovery_packs"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/workflow_recovery_packs" for item in inventory["artifacts"])
