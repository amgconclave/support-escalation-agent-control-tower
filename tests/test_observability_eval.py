from pathlib import Path

from tests.conftest import ingest_ticket


def test_trace_eval_lab_reports_trace_retrieval_and_experiment_controls(client, auth_headers):
    ticket = ingest_ticket(client, auth_headers)
    analyzed = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=auth_headers).json()

    response = client.get("/observability/trace-eval-lab", headers=auth_headers)
    assert response.status_code == 200, response.text
    lab = response.json()

    assert lab["title"] == "Trace Eval Lab"
    assert lab["local_mock_only"] is True
    assert lab["readiness_status"] == "ready"
    assert lab["observability_score"] >= 95
    assert {"trace analysis", "eval datasets", "retrieval diagnostics", "experiment comparison"} <= set(
        lab["repo_radar_patterns"]
    )
    assert any(row["run_id"] == analyzed["run_id"] for row in lab["trace_diagnostics"])
    assert lab["retrieval_diagnostics"]["citation_coverage"] >= 0.8
    assert lab["experiment_comparison"]["dataset_size"] > 0
    assert {item["variant"] for item in lab["experiment_comparison"]["variants"]} == {
        "baseline_local",
        "strict_fallback_guarded",
    }
    assert lab["summary"]["external_call_count"] == 0
    assert lab["summary"]["unsafe_auto_action_count"] == 0
    assert all(item["status"] == "pass" for item in lab["control_checks"])


def test_observability_eval_pack_exports_artifacts_and_audit_event(client, auth_headers):
    response = client.post("/observability/eval-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert exported["status"] == "ready"
    assert "observability_eval_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Trace Eval Lab Pack"
    assert pack["deployment_gate"]["status"] == "approved_for_local_demo"
    assert "## Experiment Comparison" in exported["markdown"]
    assert "retrieval" in Path(exported["json_path"]).read_text(encoding="utf-8").lower()

    events = client.get("/audit/events", headers=auth_headers).json()
    assert any(event["action"] == "observability.eval_pack_exported" for event in events)


def test_observability_eval_dashboard_contract_and_artifact_wiring(client, auth_headers):
    client.post("/observability/eval-pack", headers=auth_headers)

    smoke = client.get("/ui/dashboard-smoke", headers=auth_headers).json()
    assert smoke["status"] == "pass"
    assert any(
        item["endpoint"] == "GET /observability/trace-eval-lab"
        and item["dashboard_reference_present"]
        and item["route_present"]
        for item in smoke["endpoint_references"]
    )
    assert any(
        item["producer_endpoint"] == "POST /observability/eval-pack"
        and item["tab_present"]
        and item["endpoint_reference_present"]
        for item in smoke["generated_artifact_tabs"]
    )

    contract = client.get("/api/contract-audit", headers=auth_headers).json()
    assert "GET /observability/trace-eval-lab" in {
        item["endpoint"] for item in contract["endpoint_inventory"]
    }
    assert any(
        item["producer"] == "POST /observability/eval-pack"
        and item["artifact_directory"] == "data/observability_eval_packs"
        for item in contract["generated_artifact_endpoint_coverage"]
    )

    inventory = client.get("/artifacts/inventory", headers=auth_headers).json()
    assert any(item["directory"] == "data/observability_eval_packs" for item in inventory["artifacts"])
