from pathlib import Path


def test_enterprise_risk_register_aggregates_control_signals(client, auth_headers):
    response = client.get("/risk/register", headers=auth_headers)
    assert response.status_code == 200, response.text
    register = response.json()

    assert register["title"] == "Enterprise Risk Register"
    assert register["mode"] == "local-deterministic-enterprise-risk-register"
    assert register["local_mock_only"] is True
    assert register["risk_score"] <= 100
    assert register["summary"]["open_risk_count"] >= 1
    assert register["risk_register"]
    assert register["owner_action_plan"]
    assert register["control_signal_summary"]
    assert "GET /risk/register" in register["endpoint_list"]
    assert "POST /risk/register-pack" in register["endpoint_list"]
    assert any(item["domain"] == "Finance Impact" for item in register["risk_register"])
    assert any(item["control"] == "Access Control" for item in register["control_signal_summary"])
    assert register["limitations"]


def test_enterprise_risk_register_pack_exports_markdown_and_json(client, auth_headers):
    response = client.post("/risk/register-pack", headers=auth_headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert exported["format"] == "markdown+json"
    assert exported["readiness_status"] == pack["risk_register"]["readiness_status"]
    assert "risk_registers" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Enterprise Risk Register Pack"
    assert pack["risk_acceptance_criteria"]
    assert pack["review_cadence"]
    assert "# Enterprise Risk Register Pack" in exported["markdown"]
    assert "## Owner Action Plan" in exported["markdown"]
    saved = Path(exported["json_path"]).read_text(encoding="utf-8")
    assert "risk_register_json" in saved


def test_enterprise_risk_register_requires_auth(client):
    response = client.get("/risk/register")
    assert response.status_code in {401, 403}
