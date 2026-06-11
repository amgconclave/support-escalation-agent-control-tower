import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.storage import JsonStateStore
from app.models import AuditEvent
from app.services.analytics import AnalyticsService
from app.services.audit import AuditService
from app.services.capacity_planning import CapacityPlanningService
from app.services.customers import CustomerHealthService
from app.services.leadership import LeadershipScorecardService
from app.services.ops import OpsService
from app.services.risk_register import EnterpriseRiskRegisterService


DAILY_OPS_ENDPOINTS = [
    "GET /ops/daily-brief",
    "POST /ops/daily-brief-pack",
    "GET /analytics/ops-snapshot",
    "GET /ops/slo-budget",
    "GET /leadership/scorecard",
    "GET /customers/health",
    "GET /capacity/forecast",
    "GET /risk/register",
    "GET /approvals",
]

DAILY_OPS_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "ops/daily-brief|ops/daily-brief-pack|Executive Daily Ops Brief|'
        r'daily_ops_briefs" app dashboard docs README.md tests scripts'
    ),
]


class ExecutiveDailyOpsBriefService:
    """Composes local control-tower evidence into a daily command-center brief."""

    def __init__(
        self,
        store: JsonStateStore,
        analytics: AnalyticsService,
        ops: OpsService,
        customers: CustomerHealthService,
        capacity_planning: CapacityPlanningService,
        leadership: LeadershipScorecardService,
        risk_register: EnterpriseRiskRegisterService,
        audit: AuditService,
        daily_ops_briefs_dir: Path,
    ):
        self.store = store
        self.analytics = analytics
        self.ops = ops
        self.customers = customers
        self.capacity_planning = capacity_planning
        self.leadership = leadership
        self.risk_register = risk_register
        self.audit = audit
        self.daily_ops_briefs_dir = daily_ops_briefs_dir

    async def brief(self, app: Any) -> dict[str, Any]:
        state = await self.store.load()
        ops_snapshot = await self.analytics.ops_snapshot()
        slo_budget = await self.ops.slo_budget()
        customer_health = await self.customers.health()
        capacity = await self.capacity_planning.forecast()
        leadership = await self.leadership.scorecard()
        risk_register = await self.risk_register.register(app)

        blocked_approvals = self._blocked_approvals(state)
        sla_exposure = self._sla_exposure(ops_snapshot, slo_budget)
        engineer_load = self._engineer_load(capacity)
        critical_accounts = self._critical_accounts(customer_health)
        control_signals = self._control_signals(
            ops_snapshot,
            slo_budget,
            leadership,
            risk_register,
            capacity,
        )
        status = self._status(sla_exposure, blocked_approvals, critical_accounts, risk_register)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Executive Daily Ops Brief",
            "mode": "local-deterministic-daily-ops-brief",
            "local_mock_only": True,
            "status": status,
            "executive_summary": self._executive_summary(
                status,
                sla_exposure,
                blocked_approvals,
                critical_accounts,
                engineer_load,
                risk_register,
            ),
            "sla_exposure": sla_exposure,
            "blocked_approvals": blocked_approvals,
            "engineer_load": engineer_load,
            "critical_accounts": critical_accounts,
            "top_risky_tickets": ops_snapshot["top_risky_tickets"],
            "control_signals": control_signals,
            "recommended_actions": self._recommended_actions(
                ops_snapshot,
                slo_budget,
                blocked_approvals,
                critical_accounts,
                engineer_load,
                risk_register,
            ),
            "endpoint_list": DAILY_OPS_ENDPOINTS,
            "artifact_links": self._artifact_links(),
            "local_commands": DAILY_OPS_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self, app: Any) -> dict[str, Any]:
        brief = await self.brief(app)
        generated_at = datetime.now(timezone.utc)
        brief_id = f"daily_ops_brief_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.daily_ops_briefs_dir / f"{brief_id}.json"
        markdown_path = self.daily_ops_briefs_dir / f"{brief_id}.md"
        pack = {
            "brief_id": brief_id,
            "generated_at": generated_at.isoformat(),
            "title": "Executive Daily Ops Brief Pack",
            "daily_brief": brief,
            "decision_table": self._decision_table(brief),
            "artifact_paths": {
                "daily_ops_brief_markdown": str(markdown_path),
                "daily_ops_brief_json": str(json_path),
            },
        }
        markdown = self._markdown(pack)
        self.daily_ops_briefs_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="daily-ops-brief",
                action="ops.daily_brief_exported",
                resource_type="daily_ops_brief",
                resource_id=brief_id,
                metadata={
                    "status": brief["status"],
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                },
            )
        )
        return {
            "brief_id": brief_id,
            "format": "markdown+json",
            "status": brief["status"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    def _sla_exposure(
        self,
        ops_snapshot: dict[str, Any],
        slo_budget: dict[str, Any],
    ) -> dict[str, Any]:
        counts = ops_snapshot["counts"]["sla_risk"]
        high = counts.get("high", 0)
        medium = counts.get("medium", 0)
        exposure_score = min(100, high * 30 + medium * 12)
        status = "critical" if high >= 2 or slo_budget["overall_status"] == "fail" else "watch" if high or medium else "stable"
        return {
            "status": status,
            "exposure_score": exposure_score,
            "high_sla_risk_count": high,
            "medium_sla_risk_count": medium,
            "slo_status": slo_budget["overall_status"],
            "queue_highlights": ops_snapshot["sla_queue_highlights"][:6],
            "top_risky_ticket_count": len(ops_snapshot["top_risky_tickets"]),
        }

    def _blocked_approvals(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        tickets = state["tickets"]
        runs = state["runs"]
        rows = []
        for approval in state["approvals"].values():
            if approval.get("status") != "pending":
                continue
            created_at = self._parse_datetime(approval.get("created_at"))
            age_minutes = round((now - created_at).total_seconds() / 60, 2) if created_at else 0.0
            ticket = tickets.get(approval.get("ticket_id"), {})
            run = runs.get(approval.get("run_id"), {})
            sla_risk = run.get("state", {}).get("sla_risk", {})
            rows.append(
                {
                    "approval_id": approval["approval_id"],
                    "run_id": approval["run_id"],
                    "ticket_id": approval["ticket_id"],
                    "subject": ticket.get("subject", "unknown"),
                    "customer": ticket.get("customer") or ticket.get("account") or "unknown",
                    "priority": ticket.get("priority", "unknown"),
                    "sla_risk_level": sla_risk.get("level", "unknown"),
                    "age_minutes": age_minutes,
                    "reason": approval.get("reason", ""),
                    "recommended_action": self._approval_action(sla_risk.get("level"), age_minutes),
                }
            )
        return sorted(rows, key=lambda item: (item["sla_risk_level"] == "high", item["age_minutes"]), reverse=True)

    def _engineer_load(self, capacity: dict[str, Any]) -> dict[str, Any]:
        engineering_queues = {"api_integrations", "authentication", "incident", "security_privacy"}
        rows = [
            row
            for row in capacity["queue_forecast"]
            if row["queue"] in engineering_queues or row["status"] != "covered"
        ]
        summary = capacity["demand_summary"]
        return {
            "status": capacity["readiness_status"],
            "capacity_score": capacity["capacity_score"],
            "projected_effort_hours": summary["projected_effort_hours"],
            "capacity_gap_fte": summary["capacity_gap_fte"],
            "capacity_gap_queue_count": summary["capacity_gap_queue_count"],
            "queues": rows[:8],
            "owner_assignments": capacity["owner_assignments"][:8],
        }

    def _critical_accounts(self, customer_health: dict[str, Any]) -> list[dict[str, Any]]:
        rows = [
            customer
            for customer in customer_health["customers"]
            if customer["risk_level"] in {"critical", "at_risk"}
        ]
        return [
            {
                "customer_id": row["customer_id"],
                "account": row["account"],
                "risk_level": row["risk_level"],
                "health_score": row["health_score"],
                "ticket_count": row["ticket_count"],
                "high_sla_risk_count": row["high_sla_risk_count"],
                "pending_approval_count": row["pending_approval_count"],
                "recommended_action": row["recommended_action"],
            }
            for row in rows[:8]
        ]

    def _control_signals(
        self,
        ops_snapshot: dict[str, Any],
        slo_budget: dict[str, Any],
        leadership: dict[str, Any],
        risk_register: dict[str, Any],
        capacity: dict[str, Any],
    ) -> list[dict[str, Any]]:
        summary = ops_snapshot["summary_metrics"]
        return [
            {
                "signal": "SLA exposure",
                "status": self._signal_status(ops_snapshot["counts"]["sla_risk"].get("high", 0), 0),
                "value": ops_snapshot["counts"]["sla_risk"].get("high", 0),
                "endpoint": "GET /analytics/ops-snapshot",
            },
            {
                "signal": "Pending approvals",
                "status": self._signal_status(summary["pending_approval_count"], 3),
                "value": summary["pending_approval_count"],
                "endpoint": "GET /approvals",
            },
            {
                "signal": "SLO budget",
                "status": slo_budget["overall_status"],
                "value": slo_budget["overall_status"],
                "endpoint": "GET /ops/slo-budget",
            },
            {
                "signal": "Leadership readiness",
                "status": leadership["readiness_status"],
                "value": leadership["overall_score"],
                "endpoint": "GET /leadership/scorecard",
            },
            {
                "signal": "Capacity",
                "status": capacity["readiness_status"],
                "value": capacity["capacity_score"],
                "endpoint": "GET /capacity/forecast",
            },
            {
                "signal": "Risk register",
                "status": risk_register["readiness_status"],
                "value": risk_register["risk_score"],
                "endpoint": "GET /risk/register",
            },
        ]

    def _status(
        self,
        sla_exposure: dict[str, Any],
        blocked_approvals: list[dict[str, Any]],
        critical_accounts: list[dict[str, Any]],
        risk_register: dict[str, Any],
    ) -> str:
        if (
            sla_exposure["status"] == "critical"
            or risk_register["summary"]["critical_count"]
            or any(item["risk_level"] == "critical" for item in critical_accounts)
        ):
            return "executive_action_required"
        if blocked_approvals or critical_accounts or risk_register["summary"]["high_count"]:
            return "watchlist_review_required"
        return "stable"

    def _executive_summary(
        self,
        status: str,
        sla_exposure: dict[str, Any],
        blocked_approvals: list[dict[str, Any]],
        critical_accounts: list[dict[str, Any]],
        engineer_load: dict[str, Any],
        risk_register: dict[str, Any],
    ) -> str:
        return (
            f"Daily ops status is {status}. SLA exposure has "
            f"{sla_exposure['high_sla_risk_count']} high-risk and "
            f"{sla_exposure['medium_sla_risk_count']} medium-risk run(s), "
            f"{len(blocked_approvals)} approval(s) are blocked, "
            f"{len(critical_accounts)} account(s) require executive attention, "
            f"capacity gap is {engineer_load['capacity_gap_fte']} FTE, and the risk register "
            f"shows {risk_register['summary']['critical_count']} critical plus "
            f"{risk_register['summary']['high_count']} high risk(s)."
        )

    def _recommended_actions(
        self,
        ops_snapshot: dict[str, Any],
        slo_budget: dict[str, Any],
        blocked_approvals: list[dict[str, Any]],
        critical_accounts: list[dict[str, Any]],
        engineer_load: dict[str, Any],
        risk_register: dict[str, Any],
    ) -> list[str]:
        actions = []
        if blocked_approvals:
            first = blocked_approvals[0]
            actions.append(
                f"Clear approval {first['approval_id']} for {first['ticket_id']} before lower-risk queue work."
            )
        if ops_snapshot["counts"]["sla_risk"].get("high", 0):
            actions.append("Run a support plus engineering SLA review for high-risk tickets.")
        if critical_accounts:
            account = critical_accounts[0]
            actions.append(f"Assign CS and support owner follow-up for {account['account']}.")
        if engineer_load["capacity_gap_queue_count"]:
            actions.append("Review capacity gap queues and export the staffing plan for owner follow-up.")
        if slo_budget["overall_status"] != "pass":
            actions.append("Review SLO budget rows for latency, failures, approvals, and outbox delay.")
        if risk_register["summary"]["open_risk_count"]:
            actions.append("Work the enterprise risk register owner action plan by severity.")
        actions.extend(ops_snapshot["recommended_operational_actions"][:3])
        if not actions:
            actions.append("Continue standard queue monitoring and regenerate the brief after the next demo run.")
        return list(dict.fromkeys(actions))[:10]

    def _decision_table(self, brief: dict[str, Any]) -> list[dict[str, str]]:
        return [
            {
                "decision_area": "SLA exposure",
                "status": brief["sla_exposure"]["status"],
                "owner": "Support Operations",
                "next_action": "Prioritize high-risk tickets and blocked approvals.",
            },
            {
                "decision_area": "Engineering load",
                "status": brief["engineer_load"]["status"],
                "owner": "Engineering Manager",
                "next_action": "Review capacity gap queues and incident/API workload.",
            },
            {
                "decision_area": "Critical accounts",
                "status": "attention" if brief["critical_accounts"] else "stable",
                "owner": "Customer Success",
                "next_action": "Coordinate account follow-up for critical or at-risk customers.",
            },
            {
                "decision_area": "Risk controls",
                "status": next(
                    item["status"]
                    for item in brief["control_signals"]
                    if item["signal"] == "Risk register"
                ),
                "owner": "Support Leadership",
                "next_action": "Review open critical/high risk rows and acceptance criteria.",
            },
        ]

    def _artifact_links(self) -> dict[str, str]:
        directories = {
            "daily_ops_briefs": self.daily_ops_briefs_dir,
            "incident_briefs": self.daily_ops_briefs_dir.parent / "briefs",
            "weekly_reviews": self.daily_ops_briefs_dir.parent / "reports",
            "leadership_reviews": self.daily_ops_briefs_dir.parent / "leadership_reviews",
            "risk_registers": self.daily_ops_briefs_dir.parent / "risk_registers",
            "capacity_plans": self.daily_ops_briefs_dir.parent / "capacity_plans",
            "account_briefs": self.daily_ops_briefs_dir.parent / "account_briefs",
        }
        links = {}
        for name, directory in directories.items():
            latest = self._latest_markdown(directory)
            if latest:
                links[f"{name}_latest"] = str(latest)
        return links

    def _latest_markdown(self, directory: Path) -> Path | None:
        if not directory.exists():
            return None
        files = sorted(directory.glob("*.md"), key=lambda item: item.stat().st_mtime)
        return files[-1] if files else None

    def _approval_action(self, sla_level: str | None, age_minutes: float) -> str:
        if sla_level == "high":
            return "Escalate to support lead now; approval gates customer and engineering handoff."
        if age_minutes >= 30:
            return "Assign reviewer before next queue rotation."
        return "Keep on support lead watchlist."

    def _signal_status(self, value: int, warn_threshold: int) -> str:
        if value > warn_threshold:
            return "watch"
        return "stable"

    def _parse_datetime(self, raw: str | None) -> datetime | None:
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _limitations(self) -> list[str]:
        return [
            "The brief aggregates deterministic local control-tower state and generated artifacts only.",
            "It does not call CRM, billing, BI, workforce management, Zendesk, Jira, Slack, Azure, OpenAI, or GitHub.",
            "Capacity, account, and risk values are portfolio-grade local estimates, not systems-of-record decisions.",
            "Production use would require real-time ticket feeds, schedules, contract data, and accountable owner workflows.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        brief = pack["daily_brief"]
        decision_rows = [
            (
                f"| {row['decision_area']} | {row['status']} | "
                f"{row['owner']} | {row['next_action']} |"
            )
            for row in pack["decision_table"]
        ]
        blocked_rows = [
            (
                f"| {item['approval_id']} | {item['ticket_id']} | {item['customer']} | "
                f"{item['sla_risk_level']} | {item['age_minutes']} | {item['recommended_action']} |"
            )
            for item in brief["blocked_approvals"]
        ] or ["| None | - | - | - | 0 | No blocked approvals |"]
        account_rows = [
            (
                f"| {item['account']} | {item['risk_level']} | {item['health_score']} | "
                f"{item['high_sla_risk_count']} | {item['pending_approval_count']} | "
                f"{item['recommended_action']} |"
            )
            for item in brief["critical_accounts"]
        ] or ["| None | stable | 100 | 0 | 0 | No critical account action |"]
        queue_rows = [
            (
                f"| {item['queue']} | {item['status']} | {item['projected_effort_hours']} | "
                f"{item['capacity_gap_fte']} | {item['owner']} |"
            )
            for item in brief["engineer_load"]["queues"]
        ]
        risk_rows = [
            (
                f"| {item['ticket_id']} | {item['sla_risk_level']} | {item['sla_risk_score']} | "
                f"{item['approval_status']} | {item['recommended_action']} |"
            )
            for item in brief["top_risky_tickets"]
        ] or ["| None | low | 0 | none | No analyzed risky tickets |"]
        signal_rows = [
            f"| {item['signal']} | {item['status']} | {item['value']} | `{item['endpoint']}` |"
            for item in brief["control_signals"]
        ]
        actions = [f"- {item}" for item in brief["recommended_actions"]]
        endpoints = [f"- `{item}`" for item in brief["endpoint_list"]]
        artifacts = [
            f"- {name}: `{path}`" for name, path in sorted(brief["artifact_links"].items())
        ] or ["- No generated local evidence artifacts found yet."]
        commands = [f"- `{item}`" for item in brief["local_commands"]]
        limitations = [f"- {item}" for item in brief["limitations"]]
        return "\n".join(
            [
                f"# Executive Daily Ops Brief Pack: {pack['brief_id']}",
                "",
                brief["executive_summary"],
                "",
                "## Decision Table",
                "| Area | Status | Owner | Next Action |",
                "| --- | --- | --- | --- |",
                *decision_rows,
                "",
                "## SLA Exposure",
                f"- Status: {brief['sla_exposure']['status']}",
                f"- Exposure score: {brief['sla_exposure']['exposure_score']}",
                f"- High / medium risk: {brief['sla_exposure']['high_sla_risk_count']} / {brief['sla_exposure']['medium_sla_risk_count']}",
                f"- SLO status: {brief['sla_exposure']['slo_status']}",
                "",
                "## Blocked Approvals",
                "| Approval | Ticket | Customer | SLA Risk | Age Minutes | Action |",
                "| --- | --- | --- | --- | ---: | --- |",
                *blocked_rows,
                "",
                "## Engineer Load",
                f"- Capacity status: {brief['engineer_load']['status']}",
                f"- Capacity score: {brief['engineer_load']['capacity_score']}",
                f"- Capacity gap FTE: {brief['engineer_load']['capacity_gap_fte']}",
                "| Queue | Status | Hours | Gap FTE | Owner |",
                "| --- | --- | ---: | ---: | --- |",
                *queue_rows,
                "",
                "## Critical Accounts",
                "| Account | Risk | Health | High SLA | Pending Approvals | Action |",
                "| --- | --- | ---: | ---: | ---: | --- |",
                *account_rows,
                "",
                "## Top Risky Tickets",
                "| Ticket | SLA Risk | Score | Approval | Action |",
                "| --- | --- | ---: | --- | --- |",
                *risk_rows,
                "",
                "## Control Signals",
                "| Signal | Status | Value | Endpoint |",
                "| --- | --- | ---: | --- |",
                *signal_rows,
                "",
                "## Recommended Actions",
                *actions,
                "",
                "## Endpoints",
                *endpoints,
                "",
                "## Local Evidence Links",
                *artifacts,
                "",
                "## Local Verification Commands",
                *commands,
                "",
                "## Limitations",
                *limitations,
                "",
            ]
        )
