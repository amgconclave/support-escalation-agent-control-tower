from pathlib import Path


def _headers(client):
    token = client.post("/auth/demo-token").json()["token"]
    return {"X-API-Key": token}


def test_daily_ops_brief_summarizes_command_center_state(client):
    headers = _headers(client)
    client.post("/demo/scenario-run", headers=headers)

    response = client.get("/ops/daily-brief", headers=headers)
    assert response.status_code == 200, response.text
    brief = response.json()

    assert brief["title"] == "Executive Daily Ops Brief"
    assert brief["mode"] == "local-deterministic-daily-ops-brief"
    assert brief["local_mock_only"] is True
    assert brief["status"] in {
        "executive_action_required",
        "watchlist_review_required",
        "stable",
    }
    assert brief["sla_exposure"]["high_sla_risk_count"] >= 1
    assert brief["sla_exposure"]["slo_status"] in {"pass", "warn", "fail"}
    assert brief["blocked_approvals"]
    assert brief["engineer_load"]["queues"]
    assert brief["critical_accounts"]
    assert brief["top_risky_tickets"]
    assert brief["control_signals"]
    assert brief["recommended_actions"]
    assert "GET /ops/daily-brief" in brief["endpoint_list"]
    assert "POST /ops/daily-brief-pack" in brief["endpoint_list"]
    assert any("local" in limitation.lower() for limitation in brief["limitations"])


def test_daily_ops_brief_pack_exports_markdown_and_json(client):
    headers = _headers(client)
    client.post("/demo/scenario-run", headers=headers)

    response = client.post("/ops/daily-brief-pack", headers=headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]
    markdown = exported["markdown"]

    assert exported["status"] == pack["daily_brief"]["status"]
    assert "daily_ops_briefs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["decision_table"]
    assert pack["daily_brief"]["blocked_approvals"]
    assert pack["daily_brief"]["critical_accounts"]
    assert "daily_ops_brief_markdown" in pack["artifact_paths"]
    assert "# Executive Daily Ops Brief Pack" in markdown
    assert "## SLA Exposure" in markdown
    assert "## Blocked Approvals" in markdown
    assert "## Engineer Load" in markdown
    assert "## Critical Accounts" in markdown
    assert "## Local Verification Commands" in markdown
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "ops/daily-brief-pack" in saved
