from pathlib import Path


def _analyze(client, headers, payload):
    ticket = client.post("/tickets/ingest", headers=headers, json=payload).json()
    run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=headers).json()
    return ticket, run


def test_support_ops_crew_plan_builds_role_crews_delegation_and_modes(client, auth_headers):
    _ticket, run = _analyze(
        client,
        auth_headers,
        {
            "subject": "Enterprise SSO outage blocks login",
            "body": "Enterprise users cannot log in and the SLA clock is close to breach.",
            "customer": "Northstar Bank",
            "priority": "urgent",
            "customer_tier": "enterprise",
            "tags": ["sso", "outage", "sla"],
        },
    )

    response = client.get(f"/ops/crew-plan?run_id={run['run_id']}", headers=auth_headers)
    assert response.status_code == 200, response.text
    plan = response.json()

    assert plan["title"] == "Autonomous Support Operations Crew Plan"
    assert plan["local_mock_only"] is True
    assert plan["run_id"] == run["run_id"]
    assert plan["selected_process_mode"]["mode_id"] == "sla_war_room"
    assert {"role crews", "task delegation", "process modes"} <= set(plan["repo_radar_patterns"])
    assert {crew["role"] for crew in plan["role_crews"]} >= {
        "Support Lead",
        "Account Team",
        "Engineering Escalation Owner",
        "Operations Commander",
    }
    assert {task["crew_id"] for task in plan["delegated_tasks"]} >= {
        "support_lead_crew",
        "account_team_crew",
        "operations_commander_crew",
    }
    assert any(task["task_id"] == "engineering_escalation_handoff" for task in plan["delegated_tasks"])
    assert {gate["gate_id"] for gate in plan["review_gates"]} >= {
        "classification_sla_gate",
        "human_approval_gate",
        "delegation_completeness_gate",
    }
    assert plan["run_transparency"]["trace_id"] == run["trace_id"]
    assert plan["scenario_coverage"]["coverage_status"] == "pass"


def test_support_ops_pack_exports_markdown_json_and_audit_event(client, auth_headers):
    _analyze(
        client,
        auth_headers,
        {
            "subject": "Webhook API regression for production callbacks",
            "body": "Callbacks fail with 500s after yesterday's release and customer jobs are blocked.",
            "customer": "Atlas Logistics",
            "priority": "high",
            "customer_tier": "enterprise",
            "tags": ["webhook", "api", "regression"],
        },
    )

    response = client.post("/ops/crew-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert "support_ops_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Autonomous Support Operations Pack"
    assert pack["delegation_board"]
    assert "## Role Crews" in exported["markdown"]
    assert "## Delegated Tasks" in exported["markdown"]
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "task delegation" in saved.lower()
    assert "process modes" in saved.lower()

    events = client.get("/audit/events", headers=auth_headers).json()
    assert any(event["action"] == "ops.crew_pack_exported" for event in events)


def test_support_ops_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/ops/crew-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(item["label"] == "Support Ops Crews" and item["present"] for item in smoke["expected_views"])
    assert any(
        item["endpoint"] == "GET /ops/crew-plan"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /ops/crew-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "GET /ops/crew-plan" in {item["endpoint"] for item in contract["endpoint_inventory"]}
    assert any(
        item["producer"] == "POST /ops/crew-pack"
        and item["artifact_directory"] == "data/support_ops_packs"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/support_ops_packs" for item in inventory["artifacts"])
