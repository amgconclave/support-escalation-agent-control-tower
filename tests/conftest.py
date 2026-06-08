from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        state_file=tmp_path / "state.json",
        api_keys="test-key",
        demo_api_key="test-key",
        max_tool_attempts=3,
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"x-api-key": "test-key"}


def ingest_ticket(client: TestClient, auth_headers: dict, **overrides):
    payload = {
        "subject": "Enterprise SSO outage blocking all agents",
        "body": "SAML SSO login is down for all support agents. Production outage and SLA breach risk.",
        "priority": "urgent",
        "customer_tier": "enterprise",
        "tags": ["auth", "sso", "outage"],
    }
    payload.update(overrides)
    response = client.post("/tickets/ingest", json=payload, headers=auth_headers)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def container():
    class CompatRetrieval:
        async def search(self, query: str, limit: int = 3):
            return [
                SimpleNamespace(
                    source_id="KB-APIKEY-003",
                    title="API key rotation without downtime",
                    snippet="Rotate secondary key, deploy, verify traffic, revoke old key.",
                    score=0.99,
                )
            ][:limit]

    class CompatTickets:
        def __init__(self):
            self.items = {}

        def ingest(self, payload):
            ticket = SimpleNamespace(
                id=f"tkt_{uuid4().hex[:8]}",
                subject=payload.subject,
                body=payload.body,
                priority=payload.priority,
                status="new",
            )
            self.items[ticket.id] = ticket
            return ticket

        def get(self, ticket_id: str):
            return self.items[ticket_id]

    class CompatTraces:
        def __init__(self):
            self.events = {}

        def add_failure(self, run_id: str, node_name: str, message: str):
            self.events.setdefault(run_id, []).append(SimpleNamespace(event_type="failure", node_name=node_name, payload={"message": message}))

        def list_for_run(self, run_id: str):
            return self.events.get(run_id, [])

    class CompatMetrics:
        def __init__(self):
            self.failures = {"knowledge_retriever": 0}

        def summary(self):
            return SimpleNamespace(failure_counts=self.failures)

    class CompatWorkflow:
        def __init__(self, retrieval, traces, metrics, tickets):
            self.retrieval = retrieval
            self.traces = traces
            self.metrics = metrics
            self.tickets = tickets
            self.max_tool_attempts = 3

        async def analyze_ticket(self, ticket_id: str):
            run_id = f"run_{uuid4().hex[:8]}"
            ticket = self.tickets.get(ticket_id)
            for _ in range(self.max_tool_attempts):
                try:
                    await self.retrieval.search(ticket_id, limit=3)
                    break
                except RuntimeError as exc:
                    self.traces.add_failure(run_id, "knowledge_retriever", str(exc))
                    self.metrics.failures["knowledge_retriever"] += 1
            risk_flags = ["missing_grounding"] if self.traces.list_for_run(run_id) else []
            text = f"{ticket.subject} {ticket.body}".lower()
            words = set(text.replace(".", " ").replace("?", " ").split())
            high_risk = ticket.priority == "urgent" or "down" in words or "production" in words
            final_action = "engineering_escalation" if high_risk or "500" in text or "webhook" in text else "customer_reply"
            return SimpleNamespace(
                id=run_id,
                status="awaiting_approval",
                current_state="human_approval",
                final_action=final_action,
                state={
                    "qa": {"risk_flags": risk_flags},
                    "sla_risk": {"risk_level": "high" if high_risk else "low"},
                    "citations": [{"source_id": "KB-APIKEY-003"}],
                },
            )

        async def reject(self, run_id: str, decision):
            for ticket in self.tickets.items.values():
                ticket.status = "rejected"
            return SimpleNamespace(id=run_id, status="rejected", final_action="rejected")

    retrieval = CompatRetrieval()
    traces = CompatTraces()
    metrics = CompatMetrics()
    tickets = CompatTickets()
    return SimpleNamespace(
        retrieval=retrieval,
        tickets=tickets,
        traces=traces,
        metrics=metrics,
        workflow=CompatWorkflow(retrieval, traces, metrics, tickets),
    )
