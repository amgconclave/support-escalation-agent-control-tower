from pathlib import Path


def _headers(client):
    token = client.post("/auth/demo-token").json()["token"]
    return {"X-API-Key": token}


def test_runbook_coverage_audit_maps_tickets_to_kb_and_runbooks(client):
    headers = _headers(client)

    response = client.get("/runbooks/coverage-audit", headers=headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["mode"] == "local-deterministic-runbook-coverage-auditor"
    assert audit["local_mock_only"] is True
    assert 0 <= audit["coverage_score"] <= 100
    assert audit["coverage_summary"]["ticket_count"] >= 10
    assert audit["ticket_mappings"]
    assert audit["runbook_gaps"]
    assert "GET /runbooks/coverage-audit" in audit["endpoint_list"]
    assert "POST /runbooks/gap-pack" in audit["endpoint_list"]
    assert {
        "role playbooks",
        "task delegation",
        "process modes",
        "artifact handoffs",
        "review gates",
        "run transparency",
    } <= set(audit["repo_radar_patterns"])
    assert audit["selected_process_mode"]["mode_id"] == "urgent_gap_remediation"
    assert audit["role_playbooks"]
    assert audit["delegated_tasks"]
    assert audit["artifact_handoffs"]
    assert audit["run_transparency"]["external_calls"] == 0
    assert audit["run_transparency"]["external_services_blocked"] is True
    assert any(gate["gate_id"] == "high_impact_runbook_gate" for gate in audit["review_gates"])

    webhook = next(
        item
        for item in audit["ticket_mappings"]
        if item["ticket_id"] == "scenario:scn_webhook_api_regression"
    )
    assert webhook["ticket_type"] == "api_integrations"
    assert webhook["coverage_status"] == "covered"
    assert webhook["runbook_coverage"]["top_runbook_id"] == "pb_webhook_regression"
    assert "KB-309" in webhook["kb_coverage"]["article_ids"]

    gap_types = {gap["ticket_type"] for gap in audit["runbook_gaps"]}
    assert {"incident", "general_support"} <= gap_types
    assert any(item["owner"] == "Incident Commander" for item in audit["owner_assignments"])


def test_runbook_gap_pack_exports_owner_ready_remediation_artifacts(client):
    headers = _headers(client)

    response = client.post("/runbooks/gap-pack", headers=headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]
    markdown = exported["markdown"]

    assert exported["readiness_status"] in {
        "gaps_require_owner_remediation",
        "review_ready_with_runbook_gaps",
        "ready_for_operator_handoff",
    }
    assert "runbook_gap_packs" in exported["markdown_path"]
    assert exported["pack_id"] == pack["pack_id"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["runbook_gaps"]
    assert pack["remediation_tasks"]
    assert pack["owner_assignments"]
    assert pack["selected_process_mode"]["requires_executive_review"] is True
    assert pack["delegated_tasks"]
    assert pack["review_gates"]
    assert pack["artifact_handoffs"]
    assert pack["run_transparency"]["execution_mode"] == "local_deterministic_fixture_audit"
    assert "POST /runbooks/gap-pack" in pack["endpoint_list"]
    assert "runbook_gap_pack_markdown" in pack["artifact_paths"]
    assert "# Runbook Coverage Gap Pack" in markdown
    assert "## Ticket Coverage Map" in markdown
    assert "## Remediation Tasks" in markdown
    assert "## Review Gates" in markdown
    assert "## Artifact Handoffs" in markdown
    assert "## Run Transparency" in markdown
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "missing_dedicated_incident_runbook" in saved
