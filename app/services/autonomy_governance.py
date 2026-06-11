import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.storage import JsonStateStore
from app.models import AuditEvent, RunRecord, Ticket, TicketCreate
from app.services.audit import AuditService
from app.services.tickets import TicketService
from app.services.workflow import AgentWorkflowService, REQUIRED_WORKFLOW_NODES


GOVERNANCE_VERIFY_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "governance/autonomy-audit|governance/autonomy-pack|Autonomy Governance|'
        r'autonomy_governance_packs|tool trust|loop budget" app dashboard docs README.md tests scripts'
    ),
]

TRUSTED_TOOL_NAMES = {"internal_kb.search", "fake_zendesk", "fake_jira", "fake_slack", "playbook_recommender"}
EXTERNAL_ACTIONS = {"customer_reply_sent", "engineering_ticket_created"}


class AutonomyGovernanceService:
    """Audits autonomous loop controls, tool trust, and budget guardrails from local run state."""

    def __init__(
        self,
        store: JsonStateStore,
        tickets: TicketService,
        workflow: AgentWorkflowService,
        audit: AuditService,
        scenario_fixture: Path,
        governance_dir: Path,
    ):
        self.store = store
        self.tickets = tickets
        self.workflow = workflow
        self.audit = audit
        self.scenario_fixture = scenario_fixture
        self.governance_dir = governance_dir

    async def autonomy_audit(self) -> dict[str, Any]:
        await self._ensure_minimum_runs()
        state = await self.store.load()
        runs = [RunRecord(**raw) for raw in state["runs"].values()]
        runs.sort(key=lambda run: str(run.started_at))
        rows = [await self._run_row(run) for run in runs[-25:]]
        controls = self._control_checks(rows)
        findings = [finding for row in rows for finding in row["findings"]]
        summary = self._summary(rows, controls, findings)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Autonomy Governance Audit",
            "mode": "local-deterministic-autonomy-governance",
            "local_mock_only": True,
            "readiness_status": summary["readiness_status"],
            "governance_score": summary["governance_score"],
            "summary": summary,
            "control_checks": controls,
            "run_governance": rows,
            "finding_counts": dict(Counter(finding["severity"] for finding in findings)),
            "owner_action_plan": self._owner_actions(controls, findings),
            "policy_defaults": self._policy_defaults(),
            "repo_radar_patterns": [
                "autonomous loop controls",
                "tool governance",
                "human-in-the-loop",
                "agent cost tracking",
            ],
            "endpoint_list": [
                "GET /governance/autonomy-audit",
                "POST /governance/autonomy-pack",
                "GET /runs/{run_id}/trace",
                "GET /metrics/agent-performance",
                "GET /risk/register",
            ],
            "local_commands": GOVERNANCE_VERIFY_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self) -> dict[str, Any]:
        audit = await self.autonomy_audit()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"autonomy_governance_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.governance_dir / f"{pack_id}.json"
        markdown_path = self.governance_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Autonomy Governance and Tool Trust Pack",
            "autonomy_audit": audit,
            "decision_table": self._decision_table(audit),
            "acceptance_criteria": self._acceptance_criteria(),
            "reviewer_artifacts": {
                "autonomy_governance_markdown": str(markdown_path),
                "autonomy_governance_json": str(json_path),
                "audit_endpoint": "GET /governance/autonomy-audit",
                "export_endpoint": "POST /governance/autonomy-pack",
            },
            "local_commands": GOVERNANCE_VERIFY_COMMANDS,
            "limitations": audit["limitations"],
        }
        markdown = self._markdown(pack)
        self.governance_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="autonomy-governance",
                action="governance.autonomy_pack_exported",
                resource_type="autonomy_governance_pack",
                resource_id=pack_id,
                metadata={"markdown_path": str(markdown_path), "json_path": str(json_path)},
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": audit["readiness_status"],
            "governance_score": audit["governance_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    async def _ensure_minimum_runs(self) -> None:
        state = await self.store.load()
        if state["runs"]:
            return
        scenarios = json.loads(self.scenario_fixture.read_text(encoding="utf-8"))
        seed = next(
            scenario for scenario in scenarios if scenario["scenario_id"] == "scn_enterprise_login_outage"
        )
        payload = TicketCreate(**seed["ticket"])
        existing = await self.tickets.get_by_external_id(payload.external_id) if payload.external_id else None
        ticket = existing or await self.tickets.ingest(payload)
        await self.workflow.analyze_ticket(ticket.ticket_id)

    async def _run_row(self, run: RunRecord) -> dict[str, Any]:
        ticket = await self.tickets.get(run.ticket_id)
        tool_calls = run.state.get("tool_calls", [])
        node_history = run.state.get("node_history", [])
        metrics = run.metrics or run.state.get("metrics", {})
        findings = self._run_findings(run, tool_calls, node_history, metrics)
        total_tokens = int(metrics.get("tokens", 0) or sum(call.get("tokens", 0) for call in tool_calls))
        total_cost = float(metrics.get("cost_usd", 0.0) or sum(call.get("cost_usd", 0.0) for call in tool_calls))
        return {
            "run_id": run.run_id,
            "ticket_id": run.ticket_id,
            "trace_id": run.trace_id,
            "customer": self._customer(ticket),
            "status": str(run.status),
            "final_action": run.final_action or "pending",
            "node_count": len(node_history),
            "node_history": node_history,
            "tool_call_count": len(tool_calls),
            "tool_error_count": len([call for call in tool_calls if call.get("status") == "error"]),
            "unknown_tool_count": len([call for call in tool_calls if self._tool_name(call) not in TRUSTED_TOOL_NAMES]),
            "approval_status": run.state.get("approval_status", "unknown"),
            "approval_id": run.state.get("approval_id", ""),
            "external_action_requested": any(action in run.final_action for action in EXTERNAL_ACTIONS),
            "total_tokens": total_tokens,
            "estimated_cost_usd": round(total_cost, 6),
            "loop_budget": {
                "max_nodes": len(REQUIRED_WORKFLOW_NODES),
                "observed_nodes": len(node_history),
                "status": "pass" if len(node_history) <= len(REQUIRED_WORKFLOW_NODES) else "fail",
            },
            "tool_trust": {
                "trusted_tools": sorted(TRUSTED_TOOL_NAMES),
                "status": "pass"
                if not [call for call in tool_calls if self._tool_name(call) not in TRUSTED_TOOL_NAMES]
                else "review",
            },
            "findings": findings,
        }

    def _run_findings(
        self,
        run: RunRecord,
        tool_calls: list[dict[str, Any]],
        node_history: list[str],
        metrics: dict[str, Any],
    ) -> list[dict[str, str]]:
        findings = []
        if len(node_history) > len(REQUIRED_WORKFLOW_NODES):
            findings.append(self._finding("loop_budget_exceeded", "high", "Run exceeded workflow node budget."))
        if any(self._tool_name(call) not in TRUSTED_TOOL_NAMES for call in tool_calls):
            findings.append(self._finding("untrusted_tool_reference", "high", "Tool call used a non-allowlisted tool name."))
        if len([call for call in tool_calls if call.get("status") == "error"]) >= self.workflow.knowledge_service.max_attempts:
            findings.append(self._finding("retry_exhausted", "medium", "Tool retry errors reached the configured attempt budget."))
        if int(metrics.get("tokens", 0) or 0) > 2000:
            findings.append(self._finding("token_budget_review", "medium", "Run token use exceeded local review budget."))
        if any(action in run.final_action for action in EXTERNAL_ACTIONS) and run.state.get("approval_status") != "approved":
            findings.append(self._finding("hitl_boundary_breach", "critical", "External action appears without approved HITL state."))
        return findings

    def _control_checks(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            self._control(
                "bounded_workflow_nodes",
                "Autonomous workflow has bounded node traversal",
                all(row["loop_budget"]["status"] == "pass" for row in rows),
                "Incident Commander",
                "Keep LangGraph node order explicit and review any dynamic routing additions.",
            ),
            self._control(
                "trusted_tool_allowlist",
                "Tool calls resolve to the local trusted allowlist",
                all(row["unknown_tool_count"] == 0 for row in rows),
                "Platform AI Owner",
                "Register new tools with owner, failure mode, and data exposure notes before use.",
            ),
            self._control(
                "retry_budget_enforced",
                "Tool retry exhaustion is visible for operator review",
                True,
                "Support Ops",
                "Keep retry counts in trace and RCA evidence; use the failure drill before changing attempts.",
            ),
            self._control(
                "human_approval_before_dispatch",
                "Customer and engineering-facing actions require human approval",
                not any(
                    row["external_action_requested"] and row["approval_status"] != "approved"
                    for row in rows
                ),
                "Support Lead",
                "Block dispatch unless approval_status is approved and outbox evidence exists.",
            ),
            self._control(
                "cost_token_observability",
                "Token and cost budgets are inspectable per run",
                all("total_tokens" in row and "estimated_cost_usd" in row for row in rows),
                "AI Platform Owner",
                "Keep token/cost summaries in metrics and governance artifacts.",
            ),
        ]

    def _control(
        self,
        control_id: str,
        label: str,
        passed: bool,
        owner: str,
        remediation: str,
    ) -> dict[str, Any]:
        return {
            "control_id": control_id,
            "label": label,
            "status": "pass" if passed else "fail",
            "owner": owner,
            "remediation": remediation,
        }

    def _summary(
        self,
        rows: list[dict[str, Any]],
        controls: list[dict[str, Any]],
        findings: list[dict[str, str]],
    ) -> dict[str, Any]:
        fail_count = len([item for item in controls if item["status"] == "fail"])
        critical_count = len([item for item in findings if item["severity"] == "critical"])
        high_count = len([item for item in findings if item["severity"] == "high"])
        score = max(0, 100 - fail_count * 25 - critical_count * 30 - high_count * 15)
        return {
            "readiness_status": "blocked" if critical_count else "review" if fail_count or high_count else "ready",
            "governance_score": score,
            "run_count": len(rows),
            "control_count": len(controls),
            "failed_control_count": fail_count,
            "finding_count": len(findings),
            "critical_finding_count": critical_count,
            "high_finding_count": high_count,
            "tool_call_count": sum(row["tool_call_count"] for row in rows),
            "tool_error_count": sum(row["tool_error_count"] for row in rows),
            "estimated_cost_usd": round(sum(row["estimated_cost_usd"] for row in rows), 6),
        }

    def _owner_actions(
        self,
        controls: list[dict[str, Any]],
        findings: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        actions = [
            {
                "owner": control["owner"],
                "priority": "high" if control["status"] == "fail" else "normal",
                "action": control["remediation"],
                "evidence": control["control_id"],
            }
            for control in controls
            if control["status"] == "fail"
        ]
        if any(finding["finding_id"] == "retry_exhausted" for finding in findings):
            actions.append(
                {
                    "owner": "Support Ops",
                    "priority": "medium",
                    "action": "Review retry-exhausted runs and confirm customer-safe fallback text.",
                    "evidence": "retry_exhausted",
                }
            )
        return actions or [
            {
                "owner": "Support Ops",
                "priority": "normal",
                "action": "Keep weekly governance review cadence and regenerate the pack before release.",
                "evidence": "all_controls_passed",
            }
        ]

    def _decision_table(self, audit: dict[str, Any]) -> list[dict[str, str]]:
        return [
            {
                "signal": "Critical HITL finding",
                "decision": "block_dispatch",
                "current_state": str(audit["summary"]["critical_finding_count"]),
            },
            {
                "signal": "Untrusted tool reference",
                "decision": "security_review_required",
                "current_state": str(
                    sum(row["unknown_tool_count"] for row in audit["run_governance"])
                ),
            },
            {
                "signal": "Retry budget exhausted",
                "decision": "operator_review_required",
                "current_state": str(
                    sum(1 for row in audit["run_governance"] if row["tool_error_count"] > 0)
                ),
            },
            {
                "signal": "All controls pass",
                "decision": "local_demo_ready",
                "current_state": audit["readiness_status"],
            },
        ]

    def _policy_defaults(self) -> dict[str, Any]:
        return {
            "max_workflow_nodes": len(REQUIRED_WORKFLOW_NODES),
            "max_tool_attempts": self.workflow.knowledge_service.max_attempts,
            "trusted_tools": sorted(TRUSTED_TOOL_NAMES),
            "default_provider": "local/mock",
            "human_approval_required_for": sorted(EXTERNAL_ACTIONS),
            "review_budget": {"tokens_per_run": 2000, "cost_usd_per_run": 0.05},
        }

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Every run exposes node history, tool calls, approval state, trace ID, tokens, and cost.",
            "Workflow node traversal remains bounded and reviewable before adding dynamic autonomous loops.",
            "Tool calls use an allowlist with owners and failure-mode remediation.",
            "Customer and engineering-facing dispatch remains blocked without human approval.",
            "Governance pack is available from API, dashboard, demo output, docs, and tests.",
        ]

    def _finding(self, finding_id: str, severity: str, message: str) -> dict[str, str]:
        return {"finding_id": finding_id, "severity": severity, "message": message}

    def _limitations(self) -> list[str]:
        return [
            "The audit inspects local persisted runs and deterministic fake adapters only.",
            "It does not enforce controls at a remote gateway, queue, SaaS integration, or cloud policy engine.",
            "Cost is estimated from local metrics and mock provider accounting, not provider billing APIs.",
            "Tool trust is based on local tool-call metadata; production tools need signed manifests and RBAC.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        audit = pack["autonomy_audit"]
        summary = audit["summary"]
        controls = [
            f"| {item['control_id']} | {item['status']} | {item['owner']} | {item['remediation']} |"
            for item in audit["control_checks"]
        ]
        runs = [
            (
                f"| {item['run_id']} | {item['status']} | {item['node_count']} | "
                f"{item['tool_call_count']} | {item['approval_status']} | {len(item['findings'])} |"
            )
            for item in audit["run_governance"]
        ]
        decisions = [
            f"| {item['signal']} | {item['decision']} | {item['current_state']} |"
            for item in pack["decision_table"]
        ]
        actions = [
            f"| {item['owner']} | {item['priority']} | {item['action']} | {item['evidence']} |"
            for item in audit["owner_action_plan"]
        ]
        criteria = [f"- {item}" for item in pack["acceptance_criteria"]]
        commands = [f"- `{command}`" for command in pack["local_commands"]]
        limitations = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Autonomy Governance and Tool Trust Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: {audit['readiness_status']}",
                f"- Score: {audit['governance_score']}",
                f"- Runs audited: {summary['run_count']}",
                f"- Findings: {summary['finding_count']}",
                f"- Tool errors: {summary['tool_error_count']}",
                f"- Estimated cost: ${summary['estimated_cost_usd']}",
                "",
                "## Control Checks",
                "| Control | Status | Owner | Remediation |",
                "| --- | --- | --- | --- |",
                *controls,
                "",
                "## Run Governance",
                "| Run | Status | Nodes | Tool calls | Approval | Findings |",
                "| --- | --- | ---: | ---: | --- | ---: |",
                *runs,
                "",
                "## Decision Table",
                "| Signal | Decision | Current State |",
                "| --- | --- | --- |",
                *decisions,
                "",
                "## Owner Action Plan",
                "| Owner | Priority | Action | Evidence |",
                "| --- | --- | --- | --- |",
                *actions,
                "",
                "## Acceptance Criteria",
                *criteria,
                "",
                "## Local Commands",
                *commands,
                "",
                "## Limitations",
                *limitations,
                "",
            ]
        )

    def _customer(self, ticket: Ticket | None) -> str:
        if not ticket:
            return "unknown"
        return ticket.customer or ticket.account or ticket.customer_email

    def _tool_name(self, call: dict[str, Any]) -> str:
        return str(call.get("tool") or call.get("name") or "unknown")
