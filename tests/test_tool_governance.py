from pathlib import Path


def _analyze(client, headers):
    ticket = client.post(
        "/tickets/ingest",
        headers=headers,
        json={
            "subject": "Enterprise SSO outage blocks all login",
            "body": "SAML login is failing for all agents and SLA breach risk is high.",
            "customer": "Northstar Bank",
            "priority": "urgent",
            "customer_tier": "enterprise",
            "tags": ["sso", "outage", "sla"],
        },
    ).json()
    return client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=headers).json()


def test_tool_registry_builds_manifest_controls_and_usage(client, auth_headers):
    _analyze(client, auth_headers)

    response = client.get("/tools/registry", headers=auth_headers)
    assert response.status_code == 200, response.text
    registry = response.json()

    assert registry["title"] == "Tool Governance Registry"
    assert registry["local_mock_only"] is True
    assert registry["readiness_status"] == "ready"
    assert registry["tool_governance_score"] == 100
    assert {"tool governance", "tool trust", "marketplace governance"} <= set(
        registry["repo_radar_patterns"]
    )
    assert {item["tool_name"] for item in registry["tool_manifests"]} >= {
        "internal_kb.search",
        "fake_zendesk",
        "fake_jira",
        "fake_slack",
        "playbook_recommender",
    }
    assert all(item["control_status"] == "pass" for item in registry["tool_manifests"])
    assert registry["summary"]["observed_tool_call_count"] >= 1
    assert registry["unknown_tool_references"] == []
    assert registry["marketplace_intake_policy"]["default_decision"] == "block_until_reviewed"


def test_tool_governance_pack_exports_artifacts_and_audit_event(client, auth_headers):
    _analyze(client, auth_headers)

    response = client.post("/tools/governance-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert exported["status"] == "ready"
    assert "tool_governance_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Tool Governance and Marketplace Trust Pack"
    assert pack["approval_matrix"]
    assert "## Tool Manifests" in exported["markdown"]
    assert "## Approval Matrix" in exported["markdown"]

    events = client.get("/audit/events", headers=auth_headers).json()
    assert any(event["action"] == "tools.governance_pack_exported" for event in events)


def test_tool_governance_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/tools/governance-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(item["label"] == "Tool Governance" and item["present"] for item in smoke["expected_views"])
    assert any(
        item["endpoint"] == "GET /tools/registry"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /tools/governance-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "GET /tools/registry" in {item["endpoint"] for item in contract["endpoint_inventory"]}
    assert any(
        item["producer"] == "POST /tools/governance-pack"
        and item["artifact_directory"] == "data/tool_governance_packs"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/tool_governance_packs" for item in inventory["artifacts"])
