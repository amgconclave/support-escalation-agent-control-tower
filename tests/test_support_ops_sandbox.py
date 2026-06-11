from pathlib import Path


def _analyze(client, headers, payload):
    ticket = client.post("/tickets/ingest", headers=headers, json=payload).json()
    run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=headers).json()
    return ticket, run


def test_support_ops_sandbox_runs_workers_with_transcripts_and_gates(client, auth_headers):
    _ticket, run = _analyze(
        client,
        auth_headers,
        {
            "subject": "Webhook API regression blocks fulfillment callbacks",
            "body": "Production callbacks fail with 500s after release and enterprise jobs are blocked.",
            "customer": "Atlas Logistics",
            "priority": "high",
            "customer_tier": "enterprise",
            "tags": ["webhook", "api", "regression"],
        },
    )

    response = client.get(f"/ops/crew-sandbox?run_id={run['run_id']}", headers=auth_headers)
    assert response.status_code == 200, response.text
    sandbox = response.json()

    assert sandbox["title"] == "Support Ops Worker Sandbox Run"
    assert sandbox["local_mock_only"] is True
    assert sandbox["run_id"] == run["run_id"]
    assert sandbox["benchmark_discipline"]["status"] == "pass"
    assert sandbox["benchmark_discipline"]["score"] >= 90
    assert {"task sandbox", "run transparency", "worker scale-out"} <= set(sandbox["repo_radar_patterns"])
    assert sandbox["worker_scale_out"]["scale_decision"] == "within_local_capacity"
    assert {task_run["worker_id"] for task_run in sandbox["task_runs"]} >= {
        "support_lead_worker",
        "account_team_worker",
        "operations_commander_worker",
    }
    assert all(task_run["sandbox_mode"] == "dry_run_no_side_effects" for task_run in sandbox["task_runs"])
    assert all(task_run["budget"]["tool_calls_used"] <= task_run["budget"]["tool_call_budget"] for task_run in sandbox["task_runs"])
    assert all(
        not event["external_call"]
        for task_run in sandbox["task_runs"]
        for event in task_run["transcript"]
    )
    assert {gate["gate_id"] for gate in sandbox["verification_gates"]} >= {
        "sandbox_isolation_gate",
        "budget_gate",
        "dispatch_boundary_gate",
        "transcript_gate",
    }


def test_support_ops_sandbox_pack_exports_markdown_json_and_audit_event(client, auth_headers):
    _analyze(
        client,
        auth_headers,
        {
            "subject": "Enterprise SSO outage blocks login",
            "body": "Enterprise users cannot log in and SLA breach risk is high.",
            "customer": "Northstar Bank",
            "priority": "urgent",
            "customer_tier": "enterprise",
            "tags": ["sso", "outage", "sla"],
        },
    )

    response = client.post("/ops/crew-sandbox-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert "support_ops_sandbox" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Support Ops Worker Sandbox Pack"
    assert pack["worker_assignment_board"]
    assert pack["tool_transcript_summary"]["external_call_count"] == 0
    assert "## Worker Assignment Board" in exported["markdown"]
    assert "## Tool Transcript Budgets" in exported["markdown"]
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "task sandbox" in saved.lower()
    assert "worker scale-out" in saved.lower()

    events = client.get("/audit/events", headers=auth_headers).json()
    assert any(event["action"] == "ops.crew_sandbox_pack_exported" for event in events)


def test_support_ops_sandbox_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/ops/crew-sandbox-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(item["label"] == "Support Ops Sandbox" and item["present"] for item in smoke["expected_views"])
    assert any(
        item["endpoint"] == "GET /ops/crew-sandbox"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /ops/crew-sandbox-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "GET /ops/crew-sandbox" in {item["endpoint"] for item in contract["endpoint_inventory"]}
    assert any(
        item["producer"] == "POST /ops/crew-sandbox-pack"
        and item["artifact_directory"] == "data/support_ops_sandbox"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/support_ops_sandbox" for item in inventory["artifacts"])
