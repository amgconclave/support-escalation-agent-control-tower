import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.storage import JsonStateStore
from app.models import AuditEvent, RunRecord, RunStatus, TicketCreate
from app.services.approvals import ApprovalService
from app.services.audit import AuditService
from app.services.tickets import TicketService
from app.services.workflow import AgentWorkflowService, REQUIRED_WORKFLOW_NODES


WORKFLOW_RECOVERY_VERIFY_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "workflows/durability-audit|workflows/durability-pack|Durable Workflows|'
        r'workflow_recovery_packs|resume token|checkpoint" app dashboard docs README.md tests scripts'
    ),
]


class WorkflowRecoveryService:
    """Audits durable workflow checkpoints and human-approval resume posture."""

    def __init__(
        self,
        store: JsonStateStore,
        tickets: TicketService,
        approvals: ApprovalService,
        workflow: AgentWorkflowService,
        audit: AuditService,
        scenario_fixture: Path,
        recovery_dir: Path,
    ):
        self.store = store
        self.tickets = tickets
        self.approvals = approvals
        self.workflow = workflow
        self.audit = audit
        self.scenario_fixture = scenario_fixture
        self.recovery_dir = recovery_dir

    async def durability_audit(self) -> dict[str, Any]:
        await self._ensure_minimum_run()
        state = await self.store.load()
        runs = [RunRecord(**raw) for raw in state["runs"].values()]
        runs.sort(key=lambda run: str(run.started_at))
        rows = [await self._run_recovery_row(run) for run in runs[-25:]]
        controls = self._control_checks(rows)
        findings = [finding for row in rows for finding in row["findings"]]
        summary = self._summary(rows, controls, findings)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Durable Workflow Recovery Audit",
            "mode": "local-deterministic-workflow-durability",
            "local_mock_only": True,
            "readiness_status": summary["readiness_status"],
            "durability_score": summary["durability_score"],
            "summary": summary,
            "control_checks": controls,
            "run_recovery": rows,
            "finding_counts": dict(Counter(finding["severity"] for finding in findings)),
            "operator_recovery_queue": self._operator_recovery_queue(rows),
            "resume_policy": self._resume_policy(),
            "repo_radar_patterns": [
                "durable workflows",
                "checkpointing",
                "human-in-the-loop",
                "governance",
            ],
            "endpoint_list": [
                "GET /workflows/durability-audit",
                "POST /workflows/durability-pack",
                "GET /runs/{run_id}",
                "GET /runs/{run_id}/trace",
                "POST /runs/{run_id}/approve",
                "POST /runs/{run_id}/reject",
            ],
            "local_commands": WORKFLOW_RECOVERY_VERIFY_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self) -> dict[str, Any]:
        audit = await self.durability_audit()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"workflow_recovery_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.recovery_dir / f"{pack_id}.json"
        markdown_path = self.recovery_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Durable Workflow Recovery Pack",
            "durability_audit": audit,
            "recovery_decision_table": self._decision_table(audit),
            "operator_acceptance_criteria": self._acceptance_criteria(),
            "reviewer_artifacts": {
                "workflow_recovery_markdown": str(markdown_path),
                "workflow_recovery_json": str(json_path),
                "audit_endpoint": "GET /workflows/durability-audit",
                "export_endpoint": "POST /workflows/durability-pack",
            },
            "local_commands": WORKFLOW_RECOVERY_VERIFY_COMMANDS,
            "limitations": audit["limitations"],
        }
        markdown = self._markdown(pack)
        self.recovery_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="workflow-recovery",
                action="workflows.durability_pack_exported",
                resource_type="workflow_recovery_pack",
                resource_id=pack_id,
                metadata={"markdown_path": str(markdown_path), "json_path": str(json_path)},
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": audit["readiness_status"],
            "durability_score": audit["durability_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    async def _ensure_minimum_run(self) -> None:
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

    async def _run_recovery_row(self, run: RunRecord) -> dict[str, Any]:
        ticket = await self.tickets.get(run.ticket_id)
        approvals = await self.approvals.list_pending()
        pending_approval = next((item for item in approvals if item.run_id == run.run_id), None)
        state = run.state or {}
        checkpoints = state.get("checkpoints", [])
        node_history = state.get("node_history", [])
        completed_nodes = [item["node"] for item in checkpoints if item.get("status") == "completed"]
        missing_nodes = [node for node in REQUIRED_WORKFLOW_NODES if node in node_history and node not in completed_nodes]
        resume_status = self._resume_status(run, state, pending_approval is not None)
        findings = self._findings(run, state, checkpoints, missing_nodes, resume_status)
        return {
            "run_id": run.run_id,
            "ticket_id": run.ticket_id,
            "trace_id": run.trace_id,
            "customer": ticket.customer if ticket else "unknown",
            "status": str(run.status),
            "final_action": run.final_action or state.get("final_action", "pending"),
            "checkpoint_count": len(checkpoints),
            "expected_checkpoint_count": len(node_history),
            "latest_checkpoint": checkpoints[-1] if checkpoints else {},
            "resume_token": state.get("durability", {}).get("resume_token", ""),
            "node_history": node_history,
            "missing_checkpoint_nodes": missing_nodes,
            "approval_status": state.get("approval_status", "unknown"),
            "approval_id": state.get("approval_id", ""),
            "pending_approval_record": pending_approval is not None,
            "outbox_dispatch_safe": not self._dispatch_without_approval(run, state),
            "resume_status": resume_status,
            "findings": findings,
        }

    def _resume_status(self, run: RunRecord, state: dict[str, Any], has_pending_approval: bool) -> str:
        if str(run.status) == RunStatus.pending_approval:
            if has_pending_approval and state.get("approval_id") and state.get("drafts"):
                return "resume_ready_human_approval"
            return "needs_approval_repair"
        if str(run.status) in {RunStatus.completed, RunStatus.rejected}:
            return "terminal_replay_only"
        if str(run.status) == RunStatus.running and state.get("durability", {}).get("resume_token"):
            return "operator_resume_review"
        return "checkpoint_review"

    def _findings(
        self,
        run: RunRecord,
        state: dict[str, Any],
        checkpoints: list[dict[str, Any]],
        missing_nodes: list[str],
        resume_status: str,
    ) -> list[dict[str, str]]:
        findings = []
        if not checkpoints:
            findings.append(self._finding("missing_checkpoints", "high", "Run has no persisted node checkpoints."))
        if missing_nodes:
            findings.append(
                self._finding(
                    "checkpoint_gap",
                    "medium",
                    f"Node history has checkpoints missing for: {', '.join(missing_nodes)}.",
                )
            )
        if str(run.status) == RunStatus.pending_approval and resume_status != "resume_ready_human_approval":
            findings.append(
                self._finding(
                    "approval_resume_gap",
                    "critical",
                    "Pending approval run is missing approval or draft state required for safe resume.",
                )
            )
        if self._dispatch_without_approval(run, state):
            findings.append(
                self._finding(
                    "dispatch_boundary_gap",
                    "critical",
                    "External dispatch state exists without approved human decision.",
                )
            )
        if str(run.status) == RunStatus.running and checkpoints:
            findings.append(
                self._finding(
                    "running_run_review",
                    "medium",
                    "Running run has checkpoint evidence and should be reviewed before resume or replay.",
                )
            )
        return findings

    def _dispatch_without_approval(self, run: RunRecord, state: dict[str, Any]) -> bool:
        external_action = any(
            action in (run.final_action or state.get("final_action", ""))
            for action in ["customer_reply_sent", "engineering_ticket_created"]
        )
        return external_action and state.get("approval_status") != "approved"

    def _control_checks(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            self._control(
                "node_checkpoint_persistence",
                "Every observed workflow node has a persisted checkpoint",
                all(row["checkpoint_count"] >= row["expected_checkpoint_count"] for row in rows),
                "Platform AI Owner",
                "Persist checkpoint metadata after every node before adding dynamic routing.",
            ),
            self._control(
                "hitl_resume_ready",
                "Pending approval runs preserve drafts, approval ID, and resume token",
                all(
                    row["resume_status"] != "needs_approval_repair"
                    for row in rows
                    if row["status"] == RunStatus.pending_approval
                ),
                "Support Lead",
                "Repair approval records before asking reviewers to approve or reject.",
            ),
            self._control(
                "dispatch_boundary_safe",
                "No customer or engineering dispatch is recorded without approval",
                all(row["outbox_dispatch_safe"] for row in rows),
                "Support Operations",
                "Block dispatch from any resumed run unless approval_status is approved.",
            ),
            self._control(
                "resume_token_available",
                "Active or paused runs expose a durable resume token",
                all(
                    bool(row["resume_token"])
                    for row in rows
                    if row["status"] in {RunStatus.running, RunStatus.pending_approval}
                ),
                "Incident Commander",
                "Use the latest checkpoint resume token in operator notes and recovery packs.",
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
        score = max(0, 100 - fail_count * 20 - critical_count * 30 - high_count * 15)
        return {
            "readiness_status": "blocked" if critical_count else "review" if fail_count or high_count else "ready",
            "durability_score": score,
            "run_count": len(rows),
            "checkpoint_count": sum(row["checkpoint_count"] for row in rows),
            "resume_ready_count": len(
                [row for row in rows if row["resume_status"] == "resume_ready_human_approval"]
            ),
            "operator_review_count": len(
                [row for row in rows if row["resume_status"] == "operator_resume_review"]
            ),
            "failed_control_count": fail_count,
            "finding_count": len(findings),
            "critical_finding_count": critical_count,
            "high_finding_count": high_count,
        }

    def _operator_recovery_queue(self, rows: list[dict[str, Any]]) -> list[dict[str, str]]:
        queue = []
        for row in rows:
            if row["resume_status"] in {"resume_ready_human_approval", "operator_resume_review", "needs_approval_repair"}:
                queue.append(
                    {
                        "run_id": row["run_id"],
                        "ticket_id": row["ticket_id"],
                        "status": row["resume_status"],
                        "resume_token": row["resume_token"],
                        "recommended_action": self._recommended_action(row),
                    }
                )
        return queue

    def _recommended_action(self, row: dict[str, Any]) -> str:
        if row["resume_status"] == "resume_ready_human_approval":
            return "Review drafts, then approve or reject using the existing approval endpoint."
        if row["resume_status"] == "operator_resume_review":
            return "Inspect trace and latest checkpoint before replaying or repairing state."
        return "Repair missing approval or draft state before any dispatch decision."

    def _decision_table(self, audit: dict[str, Any]) -> list[dict[str, str]]:
        return [
            {
                "signal": "Pending run has resume token and approval record",
                "decision": "safe_for_human_review",
                "current_state": str(audit["summary"]["resume_ready_count"]),
            },
            {
                "signal": "Critical recovery finding",
                "decision": "block_dispatch",
                "current_state": str(audit["summary"]["critical_finding_count"]),
            },
            {
                "signal": "Running run with checkpoint",
                "decision": "operator_resume_review",
                "current_state": str(audit["summary"]["operator_review_count"]),
            },
            {
                "signal": "All controls pass",
                "decision": "durable_workflow_ready",
                "current_state": audit["readiness_status"],
            },
        ]

    def _resume_policy(self) -> dict[str, Any]:
        return {
            "checkpoint_store": self.store.__class__.__name__,
            "terminal_statuses": [RunStatus.completed, RunStatus.rejected],
            "human_review_status": RunStatus.pending_approval,
            "resume_requires": [
                "resume_token",
                "approval_id for customer or engineering-facing actions",
                "draft customer reply and/or engineering escalation",
                "trace events for latest checkpoint",
                "no outbox dispatch unless approval_status is approved",
            ],
            "external_services_optional": True,
        }

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Each workflow node persists a checkpoint into the durable local state store.",
            "Pending human-approval runs include approval ID, drafts, resume token, trace ID, and no dispatch.",
            "Terminal runs remain replayable from saved state and trace evidence.",
            "Operators can identify stale or running runs before replaying, approving, or rejecting.",
            "Recovery evidence is visible in API, dashboard, demo output, docs, tests, and generated artifacts.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "The audit validates local SQLite-backed run state and does not resume a partially executed LangGraph process.",
            "Recovery actions remain explicit human operations through approve, reject, replay, or repair endpoints.",
            "It does not coordinate distributed workers, queues, leases, or cloud checkpoint stores.",
            "External Zendesk, Jira, Slack, Azure, OpenAI, and GitHub services are not called.",
        ]

    def _finding(self, finding_id: str, severity: str, message: str) -> dict[str, str]:
        return {"finding_id": finding_id, "severity": severity, "message": message}

    def _markdown(self, pack: dict[str, Any]) -> str:
        audit = pack["durability_audit"]
        summary = audit["summary"]
        controls = [
            f"| {item['control_id']} | {item['status']} | {item['owner']} | {item['remediation']} |"
            for item in audit["control_checks"]
        ]
        runs = [
            (
                f"| {item['run_id']} | {item['status']} | {item['checkpoint_count']} | "
                f"{item['resume_status']} | `{item['resume_token']}` | {len(item['findings'])} |"
            )
            for item in audit["run_recovery"]
        ]
        decisions = [
            f"| {item['signal']} | {item['decision']} | {item['current_state']} |"
            for item in pack["recovery_decision_table"]
        ]
        queue = [
            (
                f"| {item['run_id']} | {item['status']} | `{item['resume_token']}` | "
                f"{item['recommended_action']} |"
            )
            for item in audit["operator_recovery_queue"]
        ]
        criteria = [f"- {item}" for item in pack["operator_acceptance_criteria"]]
        commands = [f"- `{command}`" for command in pack["local_commands"]]
        limitations = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Durable Workflow Recovery Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: {audit['readiness_status']}",
                f"- Score: {audit['durability_score']}",
                f"- Runs audited: {summary['run_count']}",
                f"- Checkpoints: {summary['checkpoint_count']}",
                f"- Resume-ready approvals: {summary['resume_ready_count']}",
                f"- Findings: {summary['finding_count']}",
                "",
                "## Control Checks",
                "| Control | Status | Owner | Remediation |",
                "| --- | --- | --- | --- |",
                *controls,
                "",
                "## Run Recovery",
                "| Run | Status | Checkpoints | Resume Status | Resume Token | Findings |",
                "| --- | --- | ---: | --- | --- | ---: |",
                *runs,
                "",
                "## Operator Recovery Queue",
                "| Run | Status | Resume Token | Recommended Action |",
                "| --- | --- | --- | --- |",
                *queue,
                "",
                "## Decision Table",
                "| Signal | Decision | Current State |",
                "| --- | --- | --- |",
                *decisions,
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
