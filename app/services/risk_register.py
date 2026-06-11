import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models import AuditEvent
from app.services.access_control import AccessControlService
from app.services.audit import AuditService
from app.services.capacity_planning import CapacityPlanningService
from app.services.data_residency import DataResidencyService
from app.services.evidence_retention import EvidenceRetentionService
from app.services.finance_impact import FinanceImpactService
from app.services.knowledge import KnowledgeQualityService
from app.services.leadership import LeadershipScorecardService
from app.services.ops import OpsService
from app.services.release import ReleaseService
from app.services.runbook_coverage import RunbookCoverageService


RISK_REGISTER_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "risk/register|risk/register-pack|Enterprise Risk Register|'
        r'risk_registers" app dashboard docs README.md tests scripts'
    ),
]

RISK_ENDPOINTS = [
    "GET /risk/register",
    "POST /risk/register-pack",
    "POST /finance/impact-summary",
    "GET /capacity/forecast",
    "GET /evidence/retention-audit",
    "GET /compliance/data-residency-audit",
    "GET /security/access-matrix",
    "GET /knowledge/quality-audit",
    "GET /runbooks/coverage-audit",
    "GET /leadership/scorecard",
    "GET /release/quality-gate",
    "GET /ops/slo-budget",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_WEIGHT = {"critical": 30, "high": 18, "medium": 9, "low": 3}


class EnterpriseRiskRegisterService:
    """Aggregates local control outputs into an owner-ready risk register."""

    def __init__(
        self,
        finance_impact: FinanceImpactService,
        evidence_retention: EvidenceRetentionService,
        capacity_planning: CapacityPlanningService,
        data_residency: DataResidencyService,
        access_control: AccessControlService,
        knowledge_quality: KnowledgeQualityService,
        runbook_coverage: RunbookCoverageService,
        leadership: LeadershipScorecardService,
        release: ReleaseService,
        ops: OpsService,
        audit: AuditService,
        risk_register_dir: Path,
    ):
        self.finance_impact = finance_impact
        self.evidence_retention = evidence_retention
        self.capacity_planning = capacity_planning
        self.data_residency = data_residency
        self.access_control = access_control
        self.knowledge_quality = knowledge_quality
        self.runbook_coverage = runbook_coverage
        self.leadership = leadership
        self.release = release
        self.ops = ops
        self.audit = audit
        self.risk_register_dir = risk_register_dir

    async def register(self, app: Any) -> dict[str, Any]:
        controls = await self._control_outputs(app)
        risks = sorted(
            self._risk_rows(controls),
            key=lambda item: (SEVERITY_ORDER[item["severity"]], item["domain"], item["risk_id"]),
        )
        summary = self._summary(risks)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Enterprise Risk Register",
            "mode": "local-deterministic-enterprise-risk-register",
            "local_mock_only": True,
            "readiness_status": self._readiness_status(summary),
            "risk_score": summary["risk_score"],
            "summary": summary,
            "risk_register": risks,
            "owner_action_plan": self._owner_action_plan(risks),
            "control_signal_summary": self._control_signal_summary(controls),
            "endpoint_list": RISK_ENDPOINTS,
            "local_commands": RISK_REGISTER_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self, app: Any) -> dict[str, Any]:
        register = await self.register(app)
        generated_at = datetime.now(timezone.utc)
        pack_id = f"risk_register_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.risk_register_dir / f"{pack_id}.json"
        markdown_path = self.risk_register_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Enterprise Risk Register Pack",
            "risk_register": register,
            "executive_summary": self._executive_summary(register),
            "risk_acceptance_criteria": self._acceptance_criteria(),
            "review_cadence": self._review_cadence(register),
            "local_commands": RISK_REGISTER_COMMANDS,
            "artifact_paths": {
                "risk_register_markdown": str(markdown_path),
                "risk_register_json": str(json_path),
            },
        }
        markdown = self._markdown(pack)
        self.risk_register_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="risk-register",
                action="risk.register_pack_exported",
                resource_type="risk_register",
                resource_id=pack_id,
                metadata={
                    "readiness_status": register["readiness_status"],
                    "risk_score": register["risk_score"],
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                },
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "readiness_status": register["readiness_status"],
            "risk_score": register["risk_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    async def _control_outputs(self, app: Any) -> dict[str, Any]:
        return {
            "finance": await self.finance_impact.impact_summary(),
            "evidence": await self.evidence_retention.retention_audit(),
            "capacity": await self.capacity_planning.forecast(),
            "data_residency": await self.data_residency.audit_residency(),
            "access": await self.access_control.matrix(app),
            "knowledge": await self.knowledge_quality.audit_quality(),
            "runbooks": await self.runbook_coverage.coverage_audit(),
            "leadership": await self.leadership.scorecard(),
            "release": await self.release.quality_gate(),
            "slo": await self.ops.slo_budget(),
        }

    def _risk_rows(self, controls: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        rows.extend(self._finance_risks(controls["finance"]))
        rows.extend(self._evidence_risks(controls["evidence"]))
        rows.extend(self._capacity_risks(controls["capacity"]))
        rows.extend(self._data_residency_risks(controls["data_residency"]))
        rows.extend(self._access_risks(controls["access"]))
        rows.extend(self._knowledge_risks(controls["knowledge"]))
        rows.extend(self._runbook_risks(controls["runbooks"]))
        rows.extend(self._leadership_risks(controls["leadership"]))
        rows.extend(self._release_risks(controls["release"]))
        rows.extend(self._slo_risks(controls["slo"]))
        return rows or [self._row("risk_no_open_controls", "low", "Operations", "Support Ops", "No open risks.")]

    def _finance_risks(self, finance: dict[str, Any]) -> list[dict[str, Any]]:
        rollup = finance["finance_rollup"]
        risks = []
        if rollup["readiness_status"] != "finance_ready":
            risks.append(
                self._row(
                    "risk_finance_exposure_review",
                    "critical" if rollup["estimated_financial_exposure_usd"] >= 100000 else "high",
                    "Finance Impact",
                    "Incident Commander",
                    (
                        f"Estimated exposure is ${rollup['estimated_financial_exposure_usd']:,.2f}; "
                        f"ARR at risk is ${rollup['arr_at_risk_usd']:,.2f}."
                    ),
                    source_endpoint="POST /finance/impact-summary",
                    source_status=rollup["readiness_status"],
                    recommended_action="Review finance assumptions with Support, CS, and Engineering before exec update.",
                )
            )
        return risks

    def _evidence_risks(self, evidence: dict[str, Any]) -> list[dict[str, Any]]:
        risks = []
        if evidence["status"] != "pass":
            risks.append(
                self._row(
                    "risk_evidence_custody_gap",
                    "high" if evidence["readiness_score"] < 80 else "medium",
                    "Evidence Retention",
                    "Compliance Officer",
                    f"Evidence retention status is {evidence['status']} with score {evidence['readiness_score']}.",
                    source_endpoint="GET /evidence/retention-audit",
                    source_status=evidence["status"],
                    recommended_action="Regenerate missing packs and verify run traces, approvals, outbox, and hashes.",
                )
            )
        return risks

    def _capacity_risks(self, capacity: dict[str, Any]) -> list[dict[str, Any]]:
        summary = capacity["demand_summary"]
        if summary["capacity_gap_queue_count"] == 0:
            return []
        return [
            self._row(
                "risk_support_capacity_gap",
                "high" if summary["capacity_gap_fte"] >= 0.5 else "medium",
                "Capacity Planning",
                "Support Operations",
                (
                    f"{summary['capacity_gap_queue_count']} queue(s) need capacity; "
                    f"gap is {summary['capacity_gap_fte']} FTE."
                ),
                source_endpoint="GET /capacity/forecast",
                source_status=capacity["readiness_status"],
                recommended_action="Assign queue owners and export the staffing plan before expanding automation volume.",
            )
        ]

    def _data_residency_risks(self, audit: dict[str, Any]) -> list[dict[str, Any]]:
        summary = audit["summary"]
        count = summary["critical_count"] + summary["high_count"]
        if count == 0:
            return []
        return [
            self._row(
                "risk_data_residency_review",
                "critical" if summary["critical_count"] else "high",
                "Data Residency",
                "Compliance Officer",
                f"{summary['critical_count']} critical and {summary['high_count']} high data-residency rows need review.",
                source_endpoint="GET /compliance/data-residency-audit",
                source_status=audit["readiness_status"],
                recommended_action="Resolve restricted-region, PII, and outbox exposure rows before production adapters.",
            )
        ]

    def _access_risks(self, matrix: dict[str, Any]) -> list[dict[str, Any]]:
        findings = matrix["findings"]
        critical = len(findings.get("critical", []))
        high = len(findings.get("high", []))
        if critical + high == 0:
            return []
        return [
            self._row(
                "risk_access_control_backlog",
                "critical" if critical else "high",
                "Access Control",
                "Platform Admin",
                f"Access matrix has {critical} critical and {high} high least-privilege finding(s).",
                source_endpoint="GET /security/access-matrix",
                source_status=matrix["status"],
                recommended_action="Map protected routes to production roles/scopes before real customer data is connected.",
            )
        ]

    def _knowledge_risks(self, audit: dict[str, Any]) -> list[dict[str, Any]]:
        if audit["readiness_status"] == "kb_ready":
            return []
        return [
            self._row(
                "risk_knowledge_quality_gap",
                "high" if audit["kb_coverage_score"] < 75 else "medium",
                "Knowledge Quality",
                "Support Enablement",
                f"KB readiness is {audit['readiness_status']} with score {audit['kb_coverage_score']}.",
                source_endpoint="GET /knowledge/quality-audit",
                source_status=audit["readiness_status"],
                recommended_action="Close weak, stale, conflicting, or uncited KB guidance before reducing human review.",
            )
        ]

    def _runbook_risks(self, audit: dict[str, Any]) -> list[dict[str, Any]]:
        gaps = audit["runbook_gaps"]
        if not gaps:
            return []
        has_high = any(item["severity"] == "high" for item in gaps)
        return [
            self._row(
                "risk_runbook_coverage_gap",
                "high" if has_high else "medium",
                "Runbook Coverage",
                "Engineering Reviewer",
                f"{len(gaps)} runbook coverage gap(s) remain across ticket and scenario fixtures.",
                source_endpoint="GET /runbooks/coverage-audit",
                source_status=audit["readiness_status"],
                recommended_action="Export the gap pack and add dedicated runbooks for high-impact issue categories.",
            )
        ]

    def _leadership_risks(self, scorecard: dict[str, Any]) -> list[dict[str, Any]]:
        if scorecard["readiness_status"] == "leadership_ready":
            return []
        return [
            self._row(
                "risk_leadership_readiness",
                "high" if scorecard["overall_score"] < 70 else "medium",
                "Leadership Scorecard",
                "Support Leadership",
                f"Leadership readiness is {scorecard['readiness_status']} with score {scorecard['overall_score']}.",
                source_endpoint="GET /leadership/scorecard",
                source_status=scorecard["readiness_status"],
                recommended_action="Review top scorecard risks and export the leadership review pack for owner follow-up.",
            )
        ]

    def _release_risks(self, gate: dict[str, Any]) -> list[dict[str, Any]]:
        if gate["status"] == "ready":
            return []
        return [
            self._row(
                "risk_release_quality_gate",
                "critical" if gate["status"] == "blocked" else "medium",
                "Release Quality",
                "Platform Admin",
                f"Release gate is {gate['status']} with score {gate['score']}.",
                source_endpoint="GET /release/quality-gate",
                source_status=gate["status"],
                recommended_action="Clear release blockers or document warnings in the Publish Pack before sharing.",
            )
        ]

    def _slo_risks(self, slo: dict[str, Any]) -> list[dict[str, Any]]:
        if slo["overall_status"] == "pass":
            return []
        return [
            self._row(
                "risk_slo_budget",
                "high" if slo["overall_status"] == "fail" else "medium",
                "SLO Budget",
                "Support Operations",
                f"SLO budget status is {slo['overall_status']}.",
                source_endpoint="GET /ops/slo-budget",
                source_status=slo["overall_status"],
                recommended_action="Review latency, token, cost, failure, approval, and outbox-delay budget rows.",
            )
        ]

    def _row(
        self,
        risk_id: str,
        severity: str,
        domain: str,
        owner: str,
        trigger: str,
        *,
        source_endpoint: str = "local controls",
        source_status: str = "observed",
        recommended_action: str = "Keep monitoring in the local control tower.",
    ) -> dict[str, Any]:
        return {
            "risk_id": risk_id,
            "severity": severity,
            "status": "open" if severity in {"critical", "high", "medium"} else "monitor",
            "domain": domain,
            "owner": owner,
            "trigger": trigger,
            "business_impact": self._business_impact(severity, domain),
            "source_endpoint": source_endpoint,
            "source_status": source_status,
            "recommended_action": recommended_action,
            "due_in_days": {"critical": 1, "high": 3, "medium": 7, "low": 14}[severity],
            "acceptance_criteria": self._risk_acceptance_criteria(domain),
        }

    def _summary(self, risks: list[dict[str, Any]]) -> dict[str, Any]:
        severity_counts = {severity: 0 for severity in SEVERITY_WEIGHT}
        for risk in risks:
            severity_counts[risk["severity"]] += 1
        penalty = sum(SEVERITY_WEIGHT[severity] * count for severity, count in severity_counts.items())
        risk_score = max(0, 100 - penalty)
        return {
            "risk_score": risk_score,
            "open_risk_count": len([item for item in risks if item["status"] == "open"]),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "owner_count": len({item["owner"] for item in risks}),
            "highest_severity": risks[0]["severity"] if risks else "low",
        }

    def _readiness_status(self, summary: dict[str, Any]) -> str:
        if summary["critical_count"]:
            return "executive_risk_review_required"
        if summary["high_count"]:
            return "owner_remediation_required"
        if summary["medium_count"]:
            return "review_ready_with_open_risks"
        return "risk_register_ready"

    def _owner_action_plan(self, risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for owner in sorted({item["owner"] for item in risks}):
            owner_risks = [item for item in risks if item["owner"] == owner]
            top = sorted(owner_risks, key=lambda item: SEVERITY_ORDER[item["severity"]])[0]
            rows.append(
                {
                    "owner": owner,
                    "open_risk_count": len([item for item in owner_risks if item["status"] == "open"]),
                    "highest_severity": top["severity"],
                    "next_action": top["recommended_action"],
                    "due_in_days": top["due_in_days"],
                }
            )
        return sorted(rows, key=lambda item: (SEVERITY_ORDER[item["highest_severity"]], item["owner"]))

    def _control_signal_summary(self, controls: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {
                "control": "Finance Impact",
                "status": controls["finance"]["finance_rollup"]["readiness_status"],
                "score_or_value": controls["finance"]["finance_rollup"]["estimated_financial_exposure_usd"],
                "endpoint": "POST /finance/impact-summary",
            },
            {
                "control": "Evidence Retention",
                "status": controls["evidence"]["status"],
                "score_or_value": controls["evidence"]["readiness_score"],
                "endpoint": "GET /evidence/retention-audit",
            },
            {
                "control": "Capacity Planning",
                "status": controls["capacity"]["readiness_status"],
                "score_or_value": controls["capacity"]["capacity_score"],
                "endpoint": "GET /capacity/forecast",
            },
            {
                "control": "Data Residency",
                "status": controls["data_residency"]["readiness_status"],
                "score_or_value": controls["data_residency"]["residency_score"],
                "endpoint": "GET /compliance/data-residency-audit",
            },
            {
                "control": "Access Control",
                "status": controls["access"]["status"],
                "score_or_value": controls["access"]["summary"]["least_privilege_score"],
                "endpoint": "GET /security/access-matrix",
            },
            {
                "control": "Knowledge Quality",
                "status": controls["knowledge"]["readiness_status"],
                "score_or_value": controls["knowledge"]["kb_coverage_score"],
                "endpoint": "GET /knowledge/quality-audit",
            },
            {
                "control": "Runbook Coverage",
                "status": controls["runbooks"]["readiness_status"],
                "score_or_value": controls["runbooks"]["coverage_score"],
                "endpoint": "GET /runbooks/coverage-audit",
            },
            {
                "control": "Leadership Scorecard",
                "status": controls["leadership"]["readiness_status"],
                "score_or_value": controls["leadership"]["overall_score"],
                "endpoint": "GET /leadership/scorecard",
            },
            {
                "control": "Release Quality",
                "status": controls["release"]["status"],
                "score_or_value": controls["release"]["score"],
                "endpoint": "GET /release/quality-gate",
            },
            {
                "control": "SLO Budget",
                "status": controls["slo"]["overall_status"],
                "score_or_value": controls["slo"]["overall_status"],
                "endpoint": "GET /ops/slo-budget",
            },
        ]

    def _executive_summary(self, register: dict[str, Any]) -> str:
        summary = register["summary"]
        return (
            f"Enterprise risk register status is {register['readiness_status']} with score "
            f"{register['risk_score']}. It contains {summary['open_risk_count']} open risks "
            f"owned by {summary['owner_count']} role(s), including {summary['critical_count']} critical "
            f"and {summary['high_count']} high risks."
        )

    def _review_cadence(self, register: dict[str, Any]) -> list[dict[str, str]]:
        status = register["readiness_status"]
        cadence = "daily" if status == "executive_risk_review_required" else "weekly"
        return [
            {
                "cadence": cadence,
                "owner": "Support Leadership",
                "review": "Review critical/high risks, owner actions, and acceptance criteria.",
            },
            {
                "cadence": "per demo run",
                "owner": "Support Ops",
                "review": "Regenerate local risk register after finance, capacity, access, or compliance changes.",
            },
        ]

    def _business_impact(self, severity: str, domain: str) -> str:
        if severity == "critical":
            return f"{domain} can block executive sign-off or production adapter expansion."
        if severity == "high":
            return f"{domain} can create customer, compliance, or operational exposure without owner action."
        if severity == "medium":
            return f"{domain} should be reviewed before reducing human approval gates."
        return f"{domain} is monitored as local evidence changes."

    def _risk_acceptance_criteria(self, domain: str) -> list[str]:
        return [
            f"{domain} source endpoint returns ready/pass status or the exception is explicitly accepted.",
            "Owner action has a named accountable role and a concrete due window.",
            "Generated Markdown/JSON evidence exists under ignored local data artifacts.",
        ]

    def _acceptance_criteria(self) -> list[str]:
        return [
            "No critical risks remain open before production-facing integrations are enabled.",
            "Every high risk has an owner, due window, source endpoint, and acceptance criteria.",
            "Risk register pack is regenerated after finance, compliance, capacity, access, or release changes.",
            "Limitations clearly state that local/mock outputs are not external system-of-record attestations.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "The register aggregates deterministic local control outputs only.",
            "It does not call CRM, billing, contract, GRC, HR, Zendesk, Jira, Slack, Azure, OpenAI, or GitHub.",
            "Financial, compliance, and staffing values are portfolio-grade estimates, not system-of-record decisions.",
            "Production use would require authenticated role scopes, external evidence retention, and owner workflows.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        register = pack["risk_register"]
        summary = register["summary"]
        risk_rows = [
            (
                f"| {risk['risk_id']} | {risk['severity']} | {risk['domain']} | {risk['owner']} | "
                f"{risk['source_endpoint']} | {risk['due_in_days']} |"
            )
            for risk in register["risk_register"]
        ]
        owner_rows = [
            (
                f"| {item['owner']} | {item['highest_severity']} | {item['open_risk_count']} | "
                f"{item['due_in_days']} | {item['next_action']} |"
            )
            for item in register["owner_action_plan"]
        ]
        control_rows = [
            f"| {item['control']} | {item['status']} | {item['score_or_value']} | `{item['endpoint']}` |"
            for item in register["control_signal_summary"]
        ]
        criteria = [f"- {item}" for item in pack["risk_acceptance_criteria"]]
        commands = [f"- `{item}`" for item in pack["local_commands"]]
        limitations = [f"- {item}" for item in register["limitations"]]
        return "\n".join(
            [
                f"# Enterprise Risk Register Pack: {pack['pack_id']}",
                "",
                pack["executive_summary"],
                "",
                "## Summary",
                f"- Status: `{register['readiness_status']}`",
                f"- Risk score: `{register['risk_score']}`",
                f"- Open risks: `{summary['open_risk_count']}`",
                f"- Critical/high/medium/low: "
                f"{summary['critical_count']} / {summary['high_count']} / "
                f"{summary['medium_count']} / {summary['low_count']}",
                "",
                "## Risk Register",
                "| Risk | Severity | Domain | Owner | Source | Due Days |",
                "| --- | --- | --- | --- | --- | ---: |",
                *risk_rows,
                "",
                "## Owner Action Plan",
                "| Owner | Highest Severity | Open Risks | Due Days | Next Action |",
                "| --- | --- | ---: | ---: | --- |",
                *owner_rows,
                "",
                "## Control Signals",
                "| Control | Status | Score / Value | Endpoint |",
                "| --- | --- | ---: | --- |",
                *control_rows,
                "",
                "## Acceptance Criteria",
                *criteria,
                "",
                "## Local Verification Commands",
                *commands,
                "",
                "## Limitations",
                *limitations,
                "",
            ]
        )
