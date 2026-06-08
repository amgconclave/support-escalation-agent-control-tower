from datetime import UTC, datetime, timedelta

import pytest

from app.models import TicketCreate


@pytest.mark.asyncio
async def test_retrieval_returns_citations(container):
    citations = await container.retrieval.search("api key rotation without downtime")
    assert citations
    assert citations[0].source_id == "KB-APIKEY-003"


@pytest.mark.asyncio
async def test_tool_failure_records_trace_and_human_review(container):
    async def broken_search(query: str, limit: int = 3):
        raise RuntimeError("kb offline")

    container.workflow.retrieval.search = broken_search
    ticket = container.tickets.ingest(
        TicketCreate(
            customer="Demo",
            subject="Unclear export issue",
            body="maybe export is delayed but unclear",
            priority="low",
            sla_due_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    run = await container.workflow.analyze_ticket(ticket.id)
    trace = container.traces.list_for_run(run.id)
    failures = [event for event in trace if event.event_type == "failure"]
    assert len(failures) == container.workflow.max_tool_attempts
    assert "missing_grounding" in run.state["qa"]["risk_flags"]
    assert container.metrics.summary().failure_counts["knowledge_retriever"] >= 1
