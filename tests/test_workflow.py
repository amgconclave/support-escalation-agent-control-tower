from datetime import UTC, datetime, timedelta

import pytest

from app.models import ApprovalDecision, TicketCreate


@pytest.mark.asyncio
async def test_high_sla_ticket_routes_to_engineering(container):
    ticket = container.tickets.ingest(
        TicketCreate(
            customer="Demo",
            subject="Production login loop",
            body="All users cannot login and the app is down.",
            priority="urgent",
            sla_due_at=datetime.now(UTC) + timedelta(minutes=30),
        )
    )
    run = await container.workflow.analyze_ticket(ticket.id)
    assert run.status == "awaiting_approval"
    assert run.final_action == "engineering_escalation"
    assert run.state["sla_risk"]["risk_level"] == "high"


@pytest.mark.asyncio
async def test_kb_ticket_routes_to_customer_reply(container):
    ticket = container.tickets.ingest(
        TicketCreate(
            customer="Demo",
            subject="How do we rotate an API key?",
            body="Need zero downtime API key rotation steps.",
            priority="normal",
            sla_due_at=datetime.now(UTC) + timedelta(days=2),
        )
    )
    run = await container.workflow.analyze_ticket(ticket.id)
    assert run.final_action == "customer_reply"
    assert run.state["citations"]
    assert run.current_state == "human_approval"


@pytest.mark.asyncio
async def test_reject_marks_ticket_rejected(container):
    ticket = container.tickets.ingest(
        TicketCreate(
            customer="Demo",
            subject="Webhook sync regression",
            body="Webhook deliveries return 500.",
            priority="high",
            sla_due_at=datetime.now(UTC) + timedelta(hours=2),
        )
    )
    run = await container.workflow.analyze_ticket(ticket.id)
    rejected = await container.workflow.reject(
        run.id,
        ApprovalDecision(reviewer="lead", reviewer_notes="needs edits"),
    )
    assert rejected.final_action == "rejected"
    assert container.tickets.get(ticket.id).status == "rejected"
