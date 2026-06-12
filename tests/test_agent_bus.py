from pathlib import Path


def test_agent_bus_audit_returns_roles_gates_and_readonly_boundaries(client, auth_headers):
    response = client.get("/ops/agent-bus-audit", headers=auth_headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["title"] == "Agent Communication Bus Audit"
    assert audit["mode"] == "local-readonly-agent-bus-audit"
    assert audit["local_mock_only"] is True
    assert audit["summary"]["registered_agent_count"] == 5
    assert audit["summary"]["external_call_count"] == 0
    assert {"agent roles", "task delegation", "review gates", "run transparency"} <= set(
        audit["repo_radar_patterns"]
    )
    assert {agent["agent_id"] for agent in audit["agent_registry"]} == {
        "conductor",
        "codex_cli_worker",
        "verifier",
        "repo_radar",
        "codex_ui_bridge",
    }
    assert {gate["gate_id"] for gate in audit["control_gates"]} >= {
        "registered_agent_gate",
        "readonly_sandbox_gate",
        "jsonl_integrity_gate",
        "ui_boundary_gate",
        "external_call_boundary_gate",
    }
    assert audit["readiness_status"] in {
        "ready",
        "ready_no_bus_files",
        "ready_no_messages",
        "review_malformed_messages",
    }


def test_agent_bus_pack_exports_markdown_json_and_audit_event(client, auth_headers):
    response = client.post("/ops/agent-bus-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert "agent_bus_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Agent Coordination Bus Pack"
    assert pack["review_gate_summary"]["pass_count"] >= 4
    assert "## Agent Registry" in exported["markdown"]
    assert "## Handoff Ledger" in exported["markdown"]
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "agent communication bus" in saved.lower()
    assert "codex_ui_bridge" in saved

    events = client.get("/audit/events", headers=auth_headers).json()
    assert any(event["action"] == "ops.agent_bus_pack_exported" for event in events)


def test_agent_bus_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/ops/agent-bus-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(item["label"] == "Agent Bus" and item["present"] for item in smoke["expected_views"])
    assert any(
        item["endpoint"] == "GET /ops/agent-bus-audit"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /ops/agent-bus-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "GET /ops/agent-bus-audit" in {item["endpoint"] for item in contract["endpoint_inventory"]}
    assert any(
        item["producer"] == "POST /ops/agent-bus-pack"
        and item["artifact_directory"] == "data/agent_bus_packs"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/agent_bus_packs" for item in inventory["artifacts"])
