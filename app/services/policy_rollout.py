import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models import AuditEvent, PolicyRolloutRequest
from app.services.audit import AuditService
from app.services.policy_change_simulation import (
    POLICY_CHANGE_VERIFY_COMMANDS,
    PolicyChangeSimulationService,
)


POLICY_ROLLOUT_VERIFY_COMMANDS = [
    *POLICY_CHANGE_VERIFY_COMMANDS,
    (
        r'rg "policies/rollout-plan|policies/rollout-pack|Policy Rollout|'
        r'policy_rollout_packs|canary rollout|rollback trigger" '
        r"app dashboard docs README.md tests scripts"
    ),
]


class PolicyRolloutService:
    """Turns policy simulation deltas into review gates and local rollout artifacts."""

    def __init__(
        self,
        policy_change_simulation: PolicyChangeSimulationService,
        audit: AuditService,
        rollout_dir: Path,
    ):
        self.policy_change_simulation = policy_change_simulation
        self.audit = audit
        self.rollout_dir = rollout_dir

    async def rollout_plan(self, payload: PolicyRolloutRequest | None = None) -> dict[str, Any]:
        request = payload or PolicyRolloutRequest()
        simulation = await self.policy_change_simulation.simulate(request)
        gates = self._review_gates(simulation, request)
        summary = self._summary(simulation, gates, request)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Policy Rollout Review Gate",
            "mode": "local-deterministic-policy-rollout-gate",
            "local_mock_only": True,
            "process_mode": request.process_mode,
            "status": summary["status"],
            "summary": summary,
            "policy_change_simulation": simulation,
            "review_gates": gates,
            "role_signoffs": self._role_signoffs(gates),
            "canary_rollout": self._canary_rollout(simulation, request, gates),
            "rollback_triggers": self._rollback_triggers(request),
            "run_transparency": self._run_transparency(simulation),
            "artifact_handoffs": self._artifact_handoffs(),
            "repo_radar_patterns": [
                "review gates",
                "artifact handoffs",
                "process modes",
                "run transparency",
            ],
            "endpoint_list": [
                "POST /policies/change-simulation",
                "POST /policies/change-pack",
                "POST /policies/rollout-plan",
                "POST /policies/rollout-pack",
                "GET /audit/events",
            ],
            "local_commands": POLICY_ROLLOUT_VERIFY_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self, payload: PolicyRolloutRequest | None = None) -> dict[str, Any]:
        plan = await self.rollout_plan(payload)
        generated_at = datetime.now(timezone.utc)
        pack_id = f"policy_rollout_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.rollout_dir / f"{pack_id}.json"
        markdown_path = self.rollout_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Policy Rollout Review Pack",
            "rollout_plan": plan,
            "operator_acceptance_criteria": self._acceptance_criteria(),
            "reviewer_artifacts": {
                "policy_rollout_markdown": str(markdown_path),
                "policy_rollout_json": str(json_path),
                "plan_endpoint": "POST /policies/rollout-plan",
                "export_endpoint": "POST /policies/rollout-pack",
            },
            "local_commands": POLICY_ROLLOUT_VERIFY_COMMANDS,
            "limitations": plan["limitations"],
        }
        markdown = self._markdown(pack)
        self.rollout_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="policy-rollout",
                action="policy.rollout_pack_exported",
                resource_type="policy_rollout_pack",
                resource_id=pack_id,
                metadata={
                    "status": plan["status"],
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                },
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": plan["status"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    def _review_gates(
        self,
        simulation: dict[str, Any],
        request: PolicyRolloutRequest,
    ) -> list[dict[str, Any]]:
        blast = simulation["blast_radius"]
        sla = simulation["sla_routing"]
        deltas = simulation["summary"]["deltas"]
        return [
            self._gate(
                "new_auto_allowed_budget",
                "New auto-allowed scenarios stay within rollout budget",
                blast["newly_auto_allowed_count"] <= request.max_new_auto_allowed,
                "Support Lead",
                blast["newly_auto_allowed_count"],
                request.max_new_auto_allowed,
            ),
            self._gate(
                "sla_regression_budget",
                "SLA routing regressions stay within release budget",
                sla["regression_count"] <= request.max_sla_regressions,
                "Incident Commander",
                sla["regression_count"],
                request.max_sla_regressions,
            ),
            self._gate(
                "blast_radius_budget",
                "Overall change risk stays within blast-radius budget",
                blast["overall_change_risk_score"] <= request.max_change_risk_score,
                "Policy Admin",
                blast["overall_change_risk_score"],
                request.max_change_risk_score,
            ),
            self._gate(
                "manual_review_capacity",
                "Manual review increase is acceptable for support leads",
                deltas["blocked_for_review_count"] <= 3,
                "Support Operations",
                deltas["blocked_for_review_count"],
                3,
            ),
        ]

    def _gate(
        self,
        gate_id: str,
        label: str,
        passed: bool,
        owner: str,
        observed: int | float,
        threshold: int | float,
    ) -> dict[str, Any]:
        return {
            "gate_id": gate_id,
            "label": label,
            "status": "pass" if passed else "fail",
            "owner": owner,
            "observed": observed,
            "threshold": threshold,
            "required_artifact": "policy_change_simulation",
        }

    def _summary(
        self,
        simulation: dict[str, Any],
        gates: list[dict[str, Any]],
        request: PolicyRolloutRequest,
    ) -> dict[str, Any]:
        failed = [gate for gate in gates if gate["status"] == "fail"]
        if request.process_mode == "full" and failed:
            status = "blocked"
        elif failed:
            status = "pilot_only"
        else:
            status = "ready"
        return {
            "status": status,
            "failed_gate_count": len(failed),
            "passed_gate_count": len(gates) - len(failed),
            "scenario_count": simulation["scenario_count"],
            "recommendation": self._recommendation(status, request.process_mode),
            "policy_change_recommendation": simulation["summary"]["recommendation"],
            "change_risk_score": simulation["blast_radius"]["overall_change_risk_score"],
            "newly_auto_allowed_count": simulation["blast_radius"]["newly_auto_allowed_count"],
            "sla_regression_count": simulation["sla_routing"]["regression_count"],
        }

    def _recommendation(self, status: str, process_mode: str) -> str:
        if status == "blocked":
            return "Do not roll out. Repair failed gates and rerun the local policy simulation pack."
        if status == "pilot_only":
            return "Limit rollout to shadow or canary mode with explicit reviewer signoff and rollback triggers."
        if process_mode == "shadow":
            return "Shadow mode is ready; compare decisions without changing dispatch behavior."
        return "Canary rollout is ready with daily audit review and no external dispatch automation change."

    def _role_signoffs(self, gates: list[dict[str, Any]]) -> list[dict[str, str]]:
        owners = []
        for gate in gates:
            if gate["owner"] not in owners:
                owners.append(gate["owner"])
        return [
            {
                "role": owner,
                "status": "required" if any(g["owner"] == owner and g["status"] == "fail" for g in gates) else "optional",
                "handoff": "Review gate evidence, policy-change deltas, and rollback triggers before promotion.",
            }
            for owner in owners
        ]

    def _canary_rollout(
        self,
        simulation: dict[str, Any],
        request: PolicyRolloutRequest,
        gates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        failed_gate_ids = [gate["gate_id"] for gate in gates if gate["status"] == "fail"]
        return [
            {
                "phase": "shadow_compare",
                "traffic_scope": "0% automation change",
                "entry_criteria": "Policy simulation pack exists and reviewer can inspect scenario deltas.",
                "exit_criteria": "No SLA regression and no unexplained blast-radius increase in local corpus.",
                "allowed_modes": ["shadow", "canary", "full"],
            },
            {
                "phase": "support_lead_canary",
                "traffic_scope": "10% internal policy recommendations only",
                "entry_criteria": "All review gates pass or failed gates have named owner signoff.",
                "exit_criteria": "No rollback trigger fires for one operating day of local review.",
                "allowed_modes": ["canary", "full"],
                "blocked_by": failed_gate_ids,
            },
            {
                "phase": "full_policy_promotion",
                "traffic_scope": "100% policy recommendations; dispatch still requires HITL approval",
                "entry_criteria": "Canary evidence is attached to the rollout pack.",
                "exit_criteria": "Audit event records policy rollout review completion.",
                "allowed_modes": ["full"],
                "blocked": request.process_mode != "full" or bool(failed_gate_ids),
                "scenario_count": simulation["scenario_count"],
            },
        ]

    def _rollback_triggers(self, request: PolicyRolloutRequest) -> list[dict[str, Any]]:
        return [
            {
                "trigger": "new_auto_allowed_exceeds_budget",
                "threshold": request.max_new_auto_allowed,
                "action": "Return to shadow mode and require Support Lead review.",
            },
            {
                "trigger": "sla_regression_detected",
                "threshold": request.max_sla_regressions,
                "action": "Restore previous SLA threshold and notify Incident Commander.",
            },
            {
                "trigger": "blast_radius_budget_exceeded",
                "threshold": request.max_change_risk_score,
                "action": "Freeze rollout and require Policy Admin signoff.",
            },
            {
                "trigger": "manual_review_queue_exceeds_capacity",
                "threshold": 3,
                "action": "Pause stricter confidence cutoff until reviewer coverage is available.",
            },
        ]

    def _run_transparency(self, simulation: dict[str, Any]) -> dict[str, Any]:
        changed = [row for row in simulation["scenario_results"] if row["changed"]]
        return {
            "simulation_id": simulation["simulation_id"],
            "generated_at": simulation["generated_at"],
            "scenario_count": simulation["scenario_count"],
            "changed_scenario_count": len(changed),
            "highest_risk_changed_scenarios": simulation["blast_radius"]["highest_risk_changed_scenarios"],
            "fixture_path": simulation["fixture_path"],
        }

    def _artifact_handoffs(self) -> list[dict[str, str]]:
        return [
            {
                "artifact": "Policy Change Pack",
                "producer": "POST /policies/change-pack",
                "reviewer": "Support Lead",
            },
            {
                "artifact": "Policy Rollout Review Pack",
                "producer": "POST /policies/rollout-pack",
                "reviewer": "Policy Admin",
            },
            {
                "artifact": "Audit Event",
                "producer": "GET /audit/events",
                "reviewer": "Operations Commander",
            },
        ]

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Policy rollout gates fail closed when blast radius, SLA regressions, or new auto-allow scope exceed budget.",
            "Every failed gate names a human owner and required artifact handoff.",
            "Canary phases keep customer and engineering dispatch behind existing human approval.",
            "The rollout pack includes local proof commands, scenario count, and rollback triggers.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "Rollout gates evaluate the local deterministic scenario corpus only.",
            "The service does not update production policy configuration or dispatch external actions.",
            "Canary traffic percentages are reviewer planning metadata, not live router controls.",
            "Production rollout would need tenant-scoped policy storage, identity-aware approvals, and live monitoring.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        plan = pack["rollout_plan"]
        summary = plan["summary"]
        gates = [
            (
                f"| {gate['gate_id']} | {gate['status']} | {gate['owner']} | "
                f"{gate['observed']} / {gate['threshold']} |"
            )
            for gate in plan["review_gates"]
        ]
        phases = [
            (
                f"| {phase['phase']} | {phase['traffic_scope']} | "
                f"{phase['entry_criteria']} | {phase['exit_criteria']} |"
            )
            for phase in plan["canary_rollout"]
        ]
        signoffs = [
            f"| {item['role']} | {item['status']} | {item['handoff']} |"
            for item in plan["role_signoffs"]
        ]
        rollback = [
            f"| {item['trigger']} | {item['threshold']} | {item['action']} |"
            for item in plan["rollback_triggers"]
        ]
        handoffs = [
            f"| {item['artifact']} | {item['producer']} | {item['reviewer']} |"
            for item in plan["artifact_handoffs"]
        ]
        commands = [f"- `{command}`" for command in pack["local_commands"]]
        criteria = [f"- {item}" for item in pack["operator_acceptance_criteria"]]
        limitations = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Policy Rollout Review Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: {plan['status']}",
                f"- Process mode: {plan['process_mode']}",
                f"- Recommendation: {summary['recommendation']}",
                f"- Change risk score: {summary['change_risk_score']}",
                f"- Failed gates: {summary['failed_gate_count']}",
                f"- Scenario count: {summary['scenario_count']}",
                "",
                "## Review Gates",
                "| Gate | Status | Owner | Observed / Threshold |",
                "| --- | --- | --- | --- |",
                *gates,
                "",
                "## Role Signoffs",
                "| Role | Status | Handoff |",
                "| --- | --- | --- |",
                *signoffs,
                "",
                "## Canary Rollout",
                "| Phase | Scope | Entry Criteria | Exit Criteria |",
                "| --- | --- | --- | --- |",
                *phases,
                "",
                "## Rollback Triggers",
                "| Trigger | Threshold | Action |",
                "| --- | ---: | --- |",
                *rollback,
                "",
                "## Artifact Handoffs",
                "| Artifact | Producer | Reviewer |",
                "| --- | --- | --- |",
                *handoffs,
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
