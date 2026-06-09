from pathlib import Path


def _completed_run_with_artifact(client, auth_headers):
    ticket = client.post(
        "/tickets/ingest",
        headers=auth_headers,
        json={
            "subject": "Enterprise webhook outage evidence retention review",
            "body": "Webhook deliveries are failing with 500 errors for production enterprise traffic.",
            "customer": "Northstar Health",
            "customer_email": "ops@northstar.example",
            "priority": "urgent",
            "customer_tier": "enterprise",
            "tags": ["webhook", "api", "outage", "evidence"],
        },
    ).json()
    run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=auth_headers).json()
    approved = client.post(
        f"/runs/{run['run_id']}/approve",
        headers=auth_headers,
        json={"decided_by": "evidence-test", "note": "approved for retention evidence"},
    ).json()
    brief = client.post(f"/runs/{approved['run_id']}/incident-brief", headers=auth_headers).json()
    return approved, brief


def test_evidence_retention_audit_maps_run_state_artifacts_and_hashes(client, auth_headers):
    run, brief = _completed_run_with_artifact(client, auth_headers)

    response = client.get("/evidence/retention-audit", headers=auth_headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["mode"] == "local-deterministic-evidence-retention"
    assert audit["local_mock_only"] is True
    assert audit["state_counts"]["run_count"] >= 1
    assert audit["state_counts"]["trace_event_count"] > 0
    assert audit["state_counts"]["approval_count"] >= 1
    assert audit["state_counts"]["outbox_event_count"] >= 1
    assert audit["state_counts"]["audit_event_count"] >= 1
    row = next(item for item in audit["run_evidence_map"] if item["run_id"] == run["run_id"])
    assert row["completeness_status"] == "complete"
    assert row["missing_evidence"] == []
    assert audit["artifact_summary"]["total_file_count"] >= 2
    assert audit["hash_manifest"]["file_count"] >= 2
    assert all(item["sha256"] for item in audit["hash_manifest"]["files"])
    assert any(item["path"] == brief["markdown_path"] for item in audit["hash_manifest"]["files"])
    assert audit["retention_controls"]
    assert audit["limitations"]


def test_evidence_retention_pack_exports_markdown_and_json(client, auth_headers):
    _completed_run_with_artifact(client, auth_headers)

    response = client.post("/evidence/retention-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]
    markdown = exported["markdown"]

    assert exported["format"] == "markdown+json"
    assert "evidence_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Evidence Retention and Chain-of-Custody Pack"
    assert pack["retention_audit"]["hash_manifest"]["algorithm"] == "sha256"
    assert pack["custody_review_table"]
    assert pack["control_owner_actions"]
    assert "chain-of-custody" in markdown
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "evidence_retention_json" in saved
