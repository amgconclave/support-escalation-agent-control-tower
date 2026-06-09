from pathlib import Path


def _completed_sensitive_run(client, auth_headers):
    ticket = client.post(
        "/tickets/ingest",
        headers=auth_headers,
        json={
            "subject": "EU data export includes deleted records",
            "body": (
                "Atlas Logistics needs a privacy review for a data export that may include "
                "deleted records. Please verify request IDs before replying to dpo@atlas.example."
            ),
            "customer": "Atlas Logistics",
            "customer_email": "dpo@atlas.example",
            "priority": "high",
            "customer_tier": "enterprise",
            "tags": ["privacy", "data", "export", "compliance"],
        },
    ).json()
    run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=auth_headers).json()
    approved = client.post(
        f"/runs/{run['run_id']}/approve",
        headers=auth_headers,
        json={"decided_by": "compliance-test", "note": "approved after data residency review"},
    ).json()
    return ticket, approved


def test_data_residency_audit_flags_pii_region_and_outbox(client, auth_headers):
    ticket, _ = _completed_sensitive_run(client, auth_headers)

    response = client.get("/compliance/data-residency-audit", headers=auth_headers)
    assert response.status_code == 200, response.text
    audit = response.json()

    assert audit["mode"] == "local-deterministic-data-residency-audit"
    assert audit["local_mock_only"] is True
    assert audit["residency_score"] < 100
    assert audit["summary"]["restricted_region_ticket_count"] >= 1
    assert audit["summary"]["pii_signal_ticket_count"] >= 1
    assert audit["summary"]["outbox_exposure_ticket_count"] >= 1
    row = next(item for item in audit["account_exposure"] if item["ticket_id"] == ticket["ticket_id"])
    assert row["region"] == "EU"
    assert row["severity"] in {"high", "critical"}
    assert "restricted_region_review_required" in row["risk_reasons"]
    assert "sensitive_data_reached_integration_outbox" in row["risk_reasons"]
    assert row["human_approval_present"] is True
    assert audit["control_checks"]
    assert audit["owner_actions"]
    assert "POST /compliance/data-residency-pack" in audit["endpoint_list"]


def test_data_residency_pack_exports_markdown_and_json(client, auth_headers):
    _completed_sensitive_run(client, auth_headers)

    response = client.post("/compliance/data-residency-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert exported["format"] == "markdown+json"
    assert "data_residency_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Data Residency and PII Exposure Pack"
    assert pack["review_queue"]
    assert "Data Residency and PII Exposure Pack" in exported["markdown"]
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "data_residency_json" in saved
