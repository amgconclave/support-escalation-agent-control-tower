from pathlib import Path


def test_communication_quality_audit_scores_latest_reply(client):
    token = client.post("/auth/demo-token").json()["token"]
    headers = {"X-API-Key": token}

    response = client.get("/communications/quality-audit", headers=headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["title"] == "Customer Communication Quality Audit"
    assert audit["mode"] == "local-deterministic-communication-quality"
    assert audit["run_id"].startswith("run_")
    assert audit["trace_id"].startswith("trc_")
    assert audit["overall_score"] >= 60
    assert set(audit["score_dimensions"]) == {
        "empathy",
        "specificity",
        "policy_compliance",
        "escalation_clarity",
    }
    assert audit["quality_gate"]["gate"] == "customer_reply_pre_dispatch_review"
    assert {item["role"] for item in audit["review_crew"]} == {
        "customer_empathy_reviewer",
        "support_specificity_reviewer",
        "policy_guardrail_reviewer",
        "engineering_escalation_reviewer",
    }
    assert audit["role_playbook_handoffs"]
    assert audit["artifact_handoffs"]
    assert audit["run_transparency"]["node_history"]
    assert audit["reply_evidence"]["reply_preview"]
    assert audit["scenario_coverage"]["coverage_status"] == "pass"
    assert any("communication_quality_packs" in command for command in audit["local_proof_commands"])


def test_communication_quality_pack_writes_reviewer_artifacts(client):
    token = client.post("/auth/demo-token").json()["token"]
    headers = {"X-API-Key": token}

    response = client.post("/communications/quality-pack", headers=headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert "communication_quality_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert "# Customer Communication Quality Pack" in exported["markdown"]
    assert "## Role Crew Review" in exported["markdown"]
    assert "## Artifact Handoffs" in exported["markdown"]
    assert exported["overall_score"] == pack["quality_audit"]["overall_score"]
    assert pack["review_gate_summary"]["review_gate_pattern"] == "review_gate"
    assert pack["handoff_packet"]["run_transparency"]["approval_id"].startswith("apr_")


def test_communication_quality_flags_low_confidence_revision(client):
    token = client.post("/auth/demo-token").json()["token"]
    headers = {"X-API-Key": token}
    ticket = client.post(
        "/tickets/ingest",
        headers=headers,
        json={
            "subject": "Need help ???",
            "body": "Something looks odd.",
            "customer": "Greyline Media",
            "priority": "low",
            "customer_tier": "standard",
            "tags": [],
        },
    ).json()
    run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=headers).json()

    response = client.get(f"/communications/quality-audit?run_id={run['run_id']}", headers=headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["run_id"] == run["run_id"]
    assert audit["status"] == "blocked"
    assert any("Low-confidence QA" in item for item in audit["quality_gate"]["blockers"])
    assert any(item["owner"] == "support_lead" for item in audit["required_revisions"])


def test_dashboard_smoke_includes_communication_quality(client):
    token = client.post("/auth/demo-token").json()["token"]
    headers = {"X-API-Key": token}

    response = client.get("/ui/dashboard-smoke", headers=headers)
    assert response.status_code == 200, response.text
    smoke = response.json()

    views = {item["label"]: item for item in smoke["expected_views"]}
    endpoints = {item["endpoint"]: item for item in smoke["endpoint_references"]}
    artifacts = {item["artifact_directory"]: item for item in smoke["generated_artifact_tabs"]}

    assert smoke["status"] == "pass"
    assert views["Communication Quality"]["present"] is True
    assert endpoints["GET /communications/quality-audit"]["dashboard_reference_present"] is True
    assert endpoints["GET /communications/quality-audit"]["route_present"] is True
    assert endpoints["POST /communications/quality-pack"]["dashboard_reference_present"] is True
    assert endpoints["POST /communications/quality-pack"]["route_present"] is True
    assert artifacts["data/communication_quality_packs"]["tab_present"] is True
