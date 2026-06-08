def test_auth_and_health(client):
    assert client.get("/health").status_code == 200
    assert client.get("/tickets").status_code == 401
    token = client.post("/auth/demo-token").json()["token"]
    response = client.get("/tickets", headers={"X-API-Key": token})
    assert response.status_code == 200
    assert len(response.json()) >= 5


def test_analyze_trace_and_approval(client):
    token = client.post("/auth/demo-token").json()["token"]
    headers = {"X-API-Key": token}
    ticket = client.get("/tickets", headers=headers).json()[0]
    run = client.post(f"/tickets/{ticket['id']}/analyze", headers=headers).json()
    assert run["status"] == "awaiting_approval"
    trace = client.get(f"/runs/{run['id']}/trace", headers=headers).json()
    assert {event["node_name"] for event in trace} >= {
        "intake_classifier",
        "sla_risk_scorer",
        "knowledge_retriever",
        "customer_reply_drafter",
        "engineering_escalation_drafter",
        "qa_evaluator",
        "human_approval",
    }
    approvals = client.get("/approvals", headers=headers).json()
    assert approvals
    approved = client.post(
        f"/runs/{run['id']}/approve",
        headers=headers,
        json={"reviewer": "lead", "reviewer_notes": "ship it"},
    ).json()
    assert approved["status"] == "completed"


def test_metrics_and_audit(client):
    token = client.post("/auth/demo-token").json()["token"]
    headers = {"X-API-Key": token}
    assert "run_count" in client.get("/metrics/agent-performance", headers=headers).json()
    assert isinstance(client.get("/audit/events", headers=headers).json(), list)
