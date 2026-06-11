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
from app.services.workflow import AgentWorkflowService


COMMUNICATION_QUALITY_VERIFY_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "communications/quality-audit|communications/quality-pack|Communication Quality|'
        r'communication_quality_packs|empathy|specificity|escalation clarity" '
        r"app dashboard docs README.md tests scripts"
    ),
    (
        r"Get-ChildItem -Recurse -File data\communication_quality_packs "
        r"-ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime"
    ),
]


ROLE_CREW = [
    {
        "role": "customer_empathy_reviewer",
        "playbook": "Check acknowledgement, ownership tone, and customer-safe language before approval.",
        "decision_scope": "empathy",
    },
    {
        "role": "support_specificity_reviewer",
        "playbook": "Verify the reply names the issue, next action, owner, and evidence sources.",
        "decision_scope": "specificity",
    },
    {
        "role": "policy_guardrail_reviewer",
        "playbook": "Block promises, unsupported credits, privacy claims, or customer-visible dispatch without approval.",
        "decision_scope": "policy_compliance",
    },
    {
        "role": "engineering_escalation_reviewer",
        "playbook": "Confirm high-risk replies explain escalation path, severity, impact, and ETA ownership.",
        "decision_scope": "escalation_clarity",
    },
]


class CustomerCommunicationQualityService:
    """Scores drafted customer replies before approval or dispatch."""

    def __init__(
        self,
        store: JsonStateStore,
        tickets: TicketService,
        workflow: AgentWorkflowService,
        audit: AuditService,
        scenario_fixture: Path,
        quality_pack_dir: Path,
    ):
        self.store = store
        self.tickets = tickets
        self.workflow = workflow
        self.audit = audit
        self.scenario_fixture = scenario_fixture
        self.quality_pack_dir = quality_pack_dir

    async def quality_audit(self, run_id: str | None = None) -> dict[str, Any]:
        run, ticket, source = await self._resolve_run(run_id)
        dimensions = self._score_dimensions(run, ticket)
        overall = round(sum(item["score"] for item in dimensions.values()) / len(dimensions))
        blockers = self._blockers(dimensions, run)
        status = "blocked" if blockers else "ready_for_review" if overall >= 72 else "needs_revision"
        scenario_coverage = await self._scenario_coverage()
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Customer Communication Quality Audit",
            "mode": "local-deterministic-communication-quality",
            "local_mock_only": True,
            "source": source,
            "run_id": run.run_id,
            "ticket_id": ticket.ticket_id,
            "trace_id": run.trace_id,
            "customer": ticket.customer or ticket.account or ticket.customer_email,
            "subject": ticket.subject,
            "overall_score": overall,
            "status": status,
            "quality_gate": self._quality_gate(status, overall, blockers),
            "score_dimensions": dimensions,
            "review_crew": ROLE_CREW,
            "role_playbook_handoffs": self._role_playbook_handoffs(dimensions),
            "artifact_handoffs": self._artifact_handoffs(run),
            "run_transparency": self._run_transparency(run),
            "reply_evidence": self._reply_evidence(run, ticket),
            "required_revisions": self._required_revisions(dimensions, blockers),
            "scenario_coverage": scenario_coverage,
            "local_proof_commands": COMMUNICATION_QUALITY_VERIFY_COMMANDS,
            "limitations": [
                "Scores are deterministic local heuristics for reviewer triage, not a substitute for legal or support lead approval.",
                "The service reads stored workflow drafts and never sends customer-visible messages.",
                "No Azure, OpenAI, Zendesk, Jira, Slack, GitHub, or external services are called.",
            ],
        }

    async def export_quality_pack(self, run_id: str | None = None) -> dict[str, Any]:
        audit = await self.quality_audit(run_id)
        generated_at = datetime.now(timezone.utc)
        pack_id = f"communication_quality_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.quality_pack_dir / f"{pack_id}.json"
        markdown_path = self.quality_pack_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Customer Communication Quality Pack",
            "quality_audit": audit,
            "review_gate_summary": audit["quality_gate"],
            "role_crew_review": audit["review_crew"],
            "handoff_packet": {
                "artifact_handoffs": audit["artifact_handoffs"],
                "role_playbook_handoffs": audit["role_playbook_handoffs"],
                "run_transparency": audit["run_transparency"],
            },
            "reviewer_actions": audit["required_revisions"],
            "local_proof_commands": COMMUNICATION_QUALITY_VERIFY_COMMANDS,
            "artifact_paths": {
                "communication_quality_pack_markdown": str(markdown_path),
                "communication_quality_pack_json": str(json_path),
            },
            "limitations": audit["limitations"],
        }
        markdown = self._markdown(pack)
        self.quality_pack_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="communication-quality",
                action="communications.quality_pack_exported",
                resource_type="communication_quality_pack",
                resource_id=pack_id,
                trace_id=audit["trace_id"],
                metadata={"markdown_path": str(markdown_path), "json_path": str(json_path)},
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": audit["status"],
            "overall_score": audit["overall_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    async def _resolve_run(self, run_id: str | None) -> tuple[RunRecord, Ticket, str]:
        if run_id:
            run = await self.workflow.get_run(run_id)
            return run, await self._ticket_for_run(run), "requested_run"
        state = await self.store.load()
        if state["runs"]:
            run = RunRecord(**sorted(state["runs"].values(), key=lambda item: item["started_at"])[-1])
            return run, await self._ticket_for_run(run), "latest_run"
        scenario = self._selected_scenarios()[0]
        ticket = await self._ingest_or_get_scenario_ticket(scenario)
        run = await self.workflow.analyze_ticket(ticket.ticket_id)
        return run, ticket, "scenario_bootstrap"

    async def _ticket_for_run(self, run: RunRecord) -> Ticket:
        ticket = await self.tickets.get(run.ticket_id)
        if ticket is None:
            raise KeyError(run.ticket_id)
        return ticket

    async def _ingest_or_get_scenario_ticket(self, scenario: dict[str, Any]) -> Ticket:
        payload = TicketCreate(**scenario["ticket"])
        if payload.external_id:
            existing = await self.tickets.get_by_external_id(payload.external_id)
            if existing:
                return existing
        return await self.tickets.ingest(payload)

    def _selected_scenarios(self) -> list[dict[str, Any]]:
        scenarios = json.loads(self.scenario_fixture.read_text(encoding="utf-8"))
        preferred = [
            "scn_enterprise_login_outage",
            "scn_billing_duplicate_invoice",
            "scn_privacy_data_export",
            "scn_webhook_api_regression",
            "scn_low_confidence_ambiguity",
        ]
        by_id = {item["scenario_id"]: item for item in scenarios}
        return [by_id[item] for item in preferred if item in by_id]

    async def _scenario_coverage(self) -> dict[str, Any]:
        rows = []
        for scenario in self._selected_scenarios():
            ticket = await self._ingest_or_get_scenario_ticket(scenario)
            run = await self.workflow.analyze_ticket(ticket.ticket_id)
            dimensions = self._score_dimensions(run, ticket)
            overall = round(sum(item["score"] for item in dimensions.values()) / len(dimensions))
            rows.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "domain": scenario["domain"],
                    "run_id": run.run_id,
                    "ticket_id": ticket.ticket_id,
                    "overall_score": overall,
                    "lowest_dimension": min(dimensions.items(), key=lambda item: item[1]["score"])[0],
                    "policy_pass": dimensions["policy_compliance"]["status"] == "pass",
                    "escalation_reviewed": bool(run.state.get("drafts", {}).get("engineering_escalation")),
                }
            )
        domains = Counter(row["domain"] for row in rows)
        return {
            "coverage_status": "pass" if len(rows) >= 5 and {"outage", "billing", "webhook_api"} <= set(domains) else "gap",
            "scenario_count": len(rows),
            "domains": dict(domains),
            "policy_pass_count": sum(1 for row in rows if row["policy_pass"]),
            "escalation_review_count": sum(1 for row in rows if row["escalation_reviewed"]),
            "scenarios": rows,
        }

    def _score_dimensions(self, run: RunRecord, ticket: Ticket) -> dict[str, Any]:
        reply = run.state.get("drafts", {}).get("customer_reply", "")
        engineering = run.state.get("drafts", {}).get("engineering_escalation", "")
        kb_results = run.state.get("kb_results", [])
        qa = run.state.get("qa", {})
        sla = run.state.get("sla_risk", {})
        dimensions = {
            "empathy": self._dimension(
                "empathy",
                55,
                [
                    ("thanks" in reply.lower() or "appreciate" in reply.lower(), 15, "acknowledges customer contact"),
                    ("sorry" in reply.lower() or "understand" in reply.lower(), 10, "recognizes customer impact"),
                    ("reviewing" in reply.lower() or "we found" in reply.lower(), 10, "shows active ownership"),
                    (reply.startswith(("Hi", "Hello")), 10, "uses a customer-safe greeting"),
                ],
            ),
            "specificity": self._dimension(
                "specificity",
                45,
                [
                    (ticket.subject.lower() in reply.lower(), 15, "names the customer issue"),
                    (bool(kb_results), 15, "uses retrieved knowledge evidence"),
                    (any(item.get("title", "").lower() in reply.lower() for item in kb_results), 10, "mentions KB title"),
                    (len(reply.split()) >= 24, 10, "has enough detail for reviewer context"),
                    ("support specialist" in reply.lower() or "owner" in reply.lower(), 10, "identifies an owner path"),
                ],
            ),
            "policy_compliance": self._dimension(
                "policy_compliance",
                50,
                [
                    (not self._contains_forbidden_promise(reply), 20, "avoids unapproved refunds, credits, and guarantees"),
                    ("approval" in reply.lower() or "reviewing" in reply.lower(), 15, "keeps customer action behind review"),
                    (qa.get("confidence", 1.0) >= self.workflow.low_confidence_threshold, 10, "confidence is above guardrail threshold"),
                    (run.failure_state is None, 10, "no unresolved tool failure"),
                ],
            ),
            "escalation_clarity": self._dimension(
                "escalation_clarity",
                45,
                [
                    (sla.get("level") != "high" or bool(engineering), 20, "high-risk tickets include engineering handoff"),
                    ("sla" in engineering.lower() or sla.get("level") != "high", 10, "engineering handoff names SLA risk"),
                    (ticket.body[:40].lower() in engineering.lower() or not engineering, 10, "engineering handoff carries impact context"),
                    (bool(run.state.get("approval_id")), 10, "approval gate is linked"),
                    ("engineering" in engineering.lower() or not engineering, 10, "clear engineering route when needed"),
                ],
            ),
        }
        return dimensions

    def _dimension(self, name: str, base: int, checks: list[tuple[bool, int, str]]) -> dict[str, Any]:
        passed = [label for ok, _, label in checks if ok]
        gaps = [label for ok, _, label in checks if not ok]
        score = min(100, base + sum(points for ok, points, _ in checks if ok))
        return {
            "dimension": name,
            "score": score,
            "status": "pass" if score >= 75 else "warn" if score >= 60 else "fail",
            "passed_checks": passed,
            "gaps": gaps,
        }

    def _contains_forbidden_promise(self, reply: str) -> bool:
        text = reply.lower()
        forbidden = ["guarantee", "will refund", "credit is approved", "no breach", "data is safe"]
        return any(term in text for term in forbidden)

    def _blockers(self, dimensions: dict[str, Any], run: RunRecord) -> list[str]:
        blockers = [
            f"{name} score is below review threshold"
            for name, item in dimensions.items()
            if item["status"] == "fail"
        ]
        if run.failure_state:
            blockers.append("Unresolved tool failure requires grounding review.")
        if run.state.get("qa", {}).get("confidence", 1.0) < self.workflow.low_confidence_threshold:
            blockers.append("Low-confidence QA requires support lead rewrite.")
        return list(dict.fromkeys(blockers))

    def _quality_gate(self, status: str, overall: int, blockers: list[str]) -> dict[str, Any]:
        return {
            "gate": "customer_reply_pre_dispatch_review",
            "status": status,
            "overall_score": overall,
            "approved_for_dispatch": status == "ready_for_review" and not blockers,
            "blockers": blockers,
            "review_gate_pattern": "review_gate",
            "required_approver": "support_lead",
        }

    def _role_playbook_handoffs(self, dimensions: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for role in ROLE_CREW:
            dimension = dimensions[role["decision_scope"]]
            rows.append(
                {
                    **role,
                    "status": dimension["status"],
                    "score": dimension["score"],
                    "handoff": dimension["gaps"] or ["No revision required before support lead review."],
                }
            )
        return rows

    def _artifact_handoffs(self, run: RunRecord) -> list[dict[str, str]]:
        return [
            {
                "artifact": "run_trace",
                "endpoint": f"GET /runs/{run.run_id}/trace",
                "purpose": "Reviewer can inspect the exact node and tool sequence behind the draft.",
            },
            {
                "artifact": "approval_queue",
                "endpoint": "GET /approvals",
                "purpose": "Support lead sees pending draft approval before any external action.",
            },
            {
                "artifact": "communication_quality_pack",
                "endpoint": "POST /communications/quality-pack",
                "purpose": "Markdown and JSON handoff for empathy, specificity, policy, and escalation review.",
            },
        ]

    def _run_transparency(self, run: RunRecord) -> dict[str, Any]:
        return {
            "node_history": run.state.get("node_history", []),
            "tool_call_count": len(run.state.get("tool_calls", [])),
            "failed_tool_call_count": sum(1 for item in run.state.get("tool_calls", []) if item.get("status") == "error"),
            "approval_id": run.state.get("approval_id"),
            "qa": run.state.get("qa", {}),
            "final_action": run.final_action,
        }

    def _reply_evidence(self, run: RunRecord, ticket: Ticket) -> dict[str, Any]:
        return {
            "reply_preview": run.state.get("drafts", {}).get("customer_reply", "")[:500],
            "engineering_preview": run.state.get("drafts", {}).get("engineering_escalation", "")[:500],
            "kb_citations": [
                {
                    "article_id": item.get("article_id"),
                    "title": item.get("title"),
                    "score": item.get("score"),
                }
                for item in run.state.get("kb_results", [])
            ],
            "ticket_priority": str(ticket.priority),
            "customer_tier": ticket.customer_tier,
            "classification": run.state.get("classification", {}),
            "sla_risk": run.state.get("sla_risk", {}),
        }

    def _required_revisions(self, dimensions: dict[str, Any], blockers: list[str]) -> list[dict[str, str]]:
        revisions = []
        for name, item in dimensions.items():
            for gap in item["gaps"]:
                revisions.append(
                    {
                        "dimension": name,
                        "owner": self._owner_for_dimension(name),
                        "revision": gap,
                    }
                )
        for blocker in blockers:
            revisions.append({"dimension": "quality_gate", "owner": "support_lead", "revision": blocker})
        return revisions or [
            {
                "dimension": "review_gate",
                "owner": "support_lead",
                "revision": "Approve, reject, or edit the draft in the human approval queue.",
            }
        ]

    def _owner_for_dimension(self, dimension: str) -> str:
        return {
            "empathy": "customer_comms_owner",
            "specificity": "support_owner",
            "policy_compliance": "policy_reviewer",
            "escalation_clarity": "engineering_owner",
        }.get(dimension, "support_lead")

    def _markdown(self, pack: dict[str, Any]) -> str:
        audit = pack["quality_audit"]
        dimensions = [
            f"- **{name}**: {item['score']} ({item['status']})"
            for name, item in audit["score_dimensions"].items()
        ]
        crew = [
            f"- **{item['role']}**: {item['score']} ({item['status']}) - {item['playbook']}"
            for item in audit["role_playbook_handoffs"]
        ]
        actions = [
            f"- **{item['dimension']}** ({item['owner']}): {item['revision']}"
            for item in pack["reviewer_actions"]
        ]
        handoffs = [
            f"- **{item['artifact']}**: `{item['endpoint']}` - {item['purpose']}"
            for item in audit["artifact_handoffs"]
        ]
        scenarios = [
            (
                f"| {item['scenario_id']} | {item['domain']} | {item['overall_score']} | "
                f"{item['lowest_dimension']} | {item['policy_pass']} |"
            )
            for item in audit["scenario_coverage"]["scenarios"]
        ]
        commands = [f"- `{command}`" for command in pack["local_proof_commands"]]
        limitations = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Customer Communication Quality Pack: {pack['pack_id']}",
                "",
                "## Review Gate",
                f"- Status: {audit['status']}",
                f"- Overall score: {audit['overall_score']}",
                f"- Run: `{audit['run_id']}`",
                f"- Trace: `{audit['trace_id']}`",
                "",
                "## Score Dimensions",
                *dimensions,
                "",
                "## Role Crew Review",
                *crew,
                "",
                "## Reviewer Actions",
                *actions,
                "",
                "## Artifact Handoffs",
                *handoffs,
                "",
                "## Scenario Coverage",
                "| Scenario | Domain | Overall Score | Lowest Dimension | Policy Pass |",
                "| --- | --- | --- | --- | --- |",
                *scenarios,
                "",
                "## Local Proof Commands",
                *commands,
                "",
                "## Limitations",
                *limitations,
                "",
            ]
        )
