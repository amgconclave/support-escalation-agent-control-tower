import os
from typing import Any

import requests
import streamlit as st


API_BASE = os.getenv("CONTROL_TOWER_API_BASE_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("CONTROL_TOWER_API_KEY", "demo-control-tower-key")
HEADERS = {"x-api-key": API_KEY}


def api(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    response = requests.request(
        method,
        f"{API_BASE}{path}",
        json=payload,
        headers=HEADERS,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


st.set_page_config(page_title="Escalation Control Tower", layout="wide")
st.title("Support Escalation Agent Control Tower")

health = requests.get(f"{API_BASE}/health", timeout=5).json()
st.caption(f"API: {API_BASE} | status: {health.get('status')}")

tabs = st.tabs(
    [
        "Ticket Queue",
        "Analyze Ticket",
        "Run Timeline",
        "Trace Inspector",
        "Approval Panel",
        "Metrics",
        "Audit Events",
    ]
)

with tabs[0]:
    col1, col2 = st.columns([1, 4])
    if col1.button("Load Samples", use_container_width=True):
        api("POST", "/tickets/ingest-samples")
        st.rerun()
    tickets = api("GET", "/tickets")
    col2.metric("Open tickets", len(tickets))
    st.dataframe(
        [
            {
                "ticket_id": item["ticket_id"],
                "subject": item["subject"],
                "priority": item["priority"],
                "tier": item["customer_tier"],
                "status": item["status"],
                "tags": ", ".join(item.get("tags", [])),
            }
            for item in tickets
        ],
        use_container_width=True,
        hide_index=True,
    )

with tabs[1]:
    tickets = api("GET", "/tickets")
    labels = {f"{item['subject']} | {item['ticket_id']}": item["ticket_id"] for item in tickets}
    if labels:
        selected = st.selectbox("Ticket", list(labels))
        if st.button("Analyze", type="primary"):
            run = api("POST", f"/tickets/{labels[selected]}/analyze")
            st.session_state["run_id"] = run["run_id"]
            st.success(f"Run created: {run['run_id']}")
    run_id = st.text_input("Run ID", value=st.session_state.get("run_id", ""))
    if run_id:
        st.json(api("GET", f"/runs/{run_id}"))

with tabs[2]:
    run_id = st.text_input("Timeline run ID", value=st.session_state.get("run_id", ""))
    if run_id:
        trace = api("GET", f"/runs/{run_id}/trace")
        for event in trace:
            st.markdown(
                f"**{event.get('node') or 'workflow'}** · `{event['event_type']}` · "
                f"`{event['status']}` · {round(event.get('latency_ms', 0), 2)} ms"
            )
            if event.get("message"):
                st.caption(event["message"])

with tabs[3]:
    run_id = st.text_input("Trace run ID", value=st.session_state.get("run_id", ""))
    if run_id:
        st.dataframe(api("GET", f"/runs/{run_id}/trace"), use_container_width=True, hide_index=True)

with tabs[4]:
    approvals = api("GET", "/approvals")
    st.dataframe(
        [
            {
                "approval_id": item["approval_id"],
                "run_id": item["run_id"],
                "status": item["status"],
                "reason": item["reason"],
            }
            for item in approvals
        ],
        use_container_width=True,
        hide_index=True,
    )
    if approvals:
        selected = st.selectbox("Pending approval", [f"{a['approval_id']} | {a['run_id']}" for a in approvals])
        approval = approvals[[f"{a['approval_id']} | {a['run_id']}" for a in approvals].index(selected)]
        st.text_area("Customer reply", approval["customer_reply"], height=160)
        if approval["engineering_escalation"]:
            st.text_area("Engineering escalation", approval["engineering_escalation"], height=220)
        note = st.text_input("Reviewer note", value="Reviewed in dashboard")
        left, right = st.columns(2)
        if left.button("Approve", type="primary", use_container_width=True):
            api("POST", f"/runs/{approval['run_id']}/approve", {"decided_by": "dashboard", "note": note})
            st.rerun()
        if right.button("Reject", use_container_width=True):
            api("POST", f"/runs/{approval['run_id']}/reject", {"decided_by": "dashboard", "note": note})
            st.rerun()

with tabs[5]:
    metrics = api("GET", "/metrics/agent-performance")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Runs", metrics["run_count"])
    c2.metric("Completed", metrics["completed_runs"])
    c3.metric("Pending approvals", metrics["pending_approvals"])
    c4.metric("Estimated cost", f"${metrics['estimated_cost_usd']:.6f}")
    st.json(metrics)

with tabs[6]:
    st.dataframe(api("GET", "/audit/events"), use_container_width=True, hide_index=True)
