from pathlib import Path


def test_eval_regression_gate_combines_scenario_and_trace_eval(client, auth_headers):
    response = client.post("/evals/regression-gate", headers=auth_headers)
    assert response.status_code == 200, response.text
    gate = response.json()

    assert gate["title"] == "Eval Regression Gate"
    assert gate["mode"] == "local-deterministic-eval-regression-gate"
    assert gate["local_mock_only"] is True
    assert gate["status"] == "pass"
    assert gate["gate_score"] == 100
    assert gate["summary"]["failed_gate_count"] == 0
    assert gate["summary"]["failed_scenario_count"] == 0
    assert gate["summary"]["unsafe_auto_action_count"] == 0
    assert gate["summary"]["external_call_count"] == 0
    assert {item["status"] for item in gate["review_gates"]} == {"pass"}
    assert {"benchmark discipline", "review gates", "run transparency", "artifact handoffs"} <= set(
        gate["repo_radar_patterns"]
    )
    assert "POST /evals/regression-pack" in gate["endpoint_list"]
    assert gate["scenario_artifact_handoff"]["producer"] == "POST /scenarios/eval-pack"
    assert Path(gate["scenario_artifact_handoff"]["markdown_path"]).exists()


def test_eval_regression_pack_exports_artifacts_and_audit_event(client, auth_headers):
    response = client.post("/evals/regression-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert exported["status"] == "pass"
    assert exported["gate_score"] == 100
    assert "eval_regression_gates" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Eval Regression Gate Pack"
    assert pack["release_decision"]["decision"] == "approve_local_demo_release"
    assert "## Review Gates" in exported["markdown"]
    assert "benchmark" in Path(exported["json_path"]).read_text(encoding="utf-8").lower()

    events = client.get("/audit/events", headers=auth_headers).json()
    assert any(event["action"] == "evals.regression_pack_exported" for event in events)


def test_eval_regression_gate_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/evals/regression-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(
        item["endpoint"] == "POST /evals/regression-gate"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /evals/regression-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "POST /evals/regression-gate" in {
        item["endpoint"] for item in contract["endpoint_inventory"]
    }
    assert any(
        item["producer"] == "POST /evals/regression-pack"
        and item["artifact_directory"] == "data/eval_regression_gates"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/eval_regression_gates" for item in inventory["artifacts"])
