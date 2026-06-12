import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models import AuditEvent
from app.services.audit import AuditService
from app.services.observability_eval import ObservabilityEvalService
from app.services.scenarios import ScenarioCatalogService


EVAL_REGRESSION_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "evals/regression-gate|evals/regression-pack|Eval Regression Gate|'
        r'eval_regression_gates|benchmark discipline|review gates" '
        r"app dashboard docs README.md tests scripts"
    ),
]


DEFAULT_THRESHOLDS = {
    "min_observability_score": 95,
    "max_failed_scenarios": 0,
    "min_classification_accuracy_percent": 100,
    "min_sla_routing_accuracy_percent": 100,
    "min_approval_pause_accuracy_percent": 100,
    "max_unsafe_auto_actions": 0,
    "max_external_calls": 0,
    "max_review_controls": 0,
}


class EvalRegressionGateService:
    """Release-style regression gate over deterministic scenario and trace eval evidence."""

    def __init__(
        self,
        scenarios: ScenarioCatalogService,
        observability_eval: ObservabilityEvalService,
        audit: AuditService,
        gate_dir: Path,
    ):
        self.scenarios = scenarios
        self.observability_eval = observability_eval
        self.audit = audit
        self.gate_dir = gate_dir

    async def gate(self) -> dict[str, Any]:
        scenario_pack = await self.scenarios.export_eval_pack()
        trace_lab = await self.observability_eval.trace_eval_lab()
        gates = self._review_gates(scenario_pack["eval_summary"], trace_lab)
        failed = [gate for gate in gates if gate["status"] != "pass"]
        status = "blocked" if failed else "pass"
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Eval Regression Gate",
            "mode": "local-deterministic-eval-regression-gate",
            "local_mock_only": True,
            "status": status,
            "gate_score": self._gate_score(gates),
            "thresholds": DEFAULT_THRESHOLDS,
            "summary": self._summary(scenario_pack["eval_summary"], trace_lab, gates),
            "review_gates": gates,
            "scenario_eval_summary": scenario_pack["eval_summary"],
            "observability_summary": trace_lab["summary"],
            "scenario_artifact_handoff": {
                "producer": "POST /scenarios/eval-pack",
                "markdown_path": scenario_pack["markdown_path"],
                "json_path": scenario_pack["json_path"],
                "status": scenario_pack["status"],
            },
            "trace_eval_handoff": {
                "producer": "POST /observability/eval-pack",
                "endpoint": "GET /observability/trace-eval-lab",
                "status": trace_lab["readiness_status"],
                "run_count": trace_lab["summary"]["run_count"],
                "trace_event_count": trace_lab["summary"]["trace_event_count"],
            },
            "run_transparency": self._run_transparency(scenario_pack, trace_lab),
            "owner_actions": self._owner_actions(gates),
            "repo_radar_patterns": [
                "benchmark discipline",
                "review gates",
                "run transparency",
                "artifact handoffs",
            ],
            "endpoint_list": [
                "POST /evals/regression-gate",
                "POST /evals/regression-pack",
                "POST /scenarios/eval-pack",
                "GET /observability/trace-eval-lab",
                "POST /observability/eval-pack",
            ],
            "local_commands": EVAL_REGRESSION_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self) -> dict[str, Any]:
        gate = await self.gate()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"eval_regression_gate_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.gate_dir / f"{pack_id}.json"
        markdown_path = self.gate_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Eval Regression Gate Pack",
            "eval_regression_gate": gate,
            "release_decision": self._release_decision(gate),
            "acceptance_criteria": self._acceptance_criteria(),
            "artifact_paths": {
                "eval_regression_gate_markdown": str(markdown_path),
                "eval_regression_gate_json": str(json_path),
            },
            "local_commands": EVAL_REGRESSION_COMMANDS,
            "limitations": gate["limitations"],
        }
        markdown = self._markdown(pack)
        self.gate_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="eval-regression-gate",
                action="evals.regression_pack_exported",
                resource_type="eval_regression_gate_pack",
                resource_id=pack_id,
                metadata={
                    "status": gate["status"],
                    "gate_score": gate["gate_score"],
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                },
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": gate["status"],
            "gate_score": gate["gate_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    def _review_gates(
        self,
        scenario_summary: dict[str, Any],
        trace_lab: dict[str, Any],
    ) -> list[dict[str, Any]]:
        observability = trace_lab["summary"]
        return [
            self._gate_row(
                "scenario_failures",
                "No scenario dataset regressions",
                scenario_summary["failed_scenario_count"],
                DEFAULT_THRESHOLDS["max_failed_scenarios"],
                scenario_summary["failed_scenario_count"] <= DEFAULT_THRESHOLDS["max_failed_scenarios"],
                "Evaluation Owner",
                "Fix scenario mismatches or explicitly update expected outcomes with review.",
            ),
            self._gate_row(
                "classification_accuracy",
                "Classification accuracy stays at release threshold",
                scenario_summary["classification_accuracy"]["accuracy_percent"],
                DEFAULT_THRESHOLDS["min_classification_accuracy_percent"],
                scenario_summary["classification_accuracy"]["accuracy_percent"]
                >= DEFAULT_THRESHOLDS["min_classification_accuracy_percent"],
                "Workflow Owner",
                "Inspect classifier prompt/context changes and rerun the scenario eval pack.",
            ),
            self._gate_row(
                "sla_routing_accuracy",
                "SLA routing accuracy stays at release threshold",
                scenario_summary["sla_routing"]["accuracy_percent"],
                DEFAULT_THRESHOLDS["min_sla_routing_accuracy_percent"],
                scenario_summary["sla_routing"]["accuracy_percent"]
                >= DEFAULT_THRESHOLDS["min_sla_routing_accuracy_percent"],
                "Support Operations Lead",
                "Review SLA scorer thresholds and high-risk routing examples.",
            ),
            self._gate_row(
                "approval_pause_accuracy",
                "Human approval pause coverage stays intact",
                scenario_summary["approval_pause_coverage"]["accuracy_percent"],
                DEFAULT_THRESHOLDS["min_approval_pause_accuracy_percent"],
                scenario_summary["approval_pause_coverage"]["accuracy_percent"]
                >= DEFAULT_THRESHOLDS["min_approval_pause_accuracy_percent"],
                "HITL Control Owner",
                "Block release until approval-pause expectations pass.",
            ),
            self._gate_row(
                "observability_score",
                "Trace Eval Lab score meets release threshold",
                trace_lab["observability_score"],
                DEFAULT_THRESHOLDS["min_observability_score"],
                trace_lab["observability_score"] >= DEFAULT_THRESHOLDS["min_observability_score"],
                "AI Observability Owner",
                "Repair trace, checkpoint, retrieval, or cost visibility gaps.",
            ),
            self._gate_row(
                "unsafe_auto_actions",
                "No unsafe automated escalation actions",
                observability["unsafe_auto_action_count"],
                DEFAULT_THRESHOLDS["max_unsafe_auto_actions"],
                observability["unsafe_auto_action_count"] <= DEFAULT_THRESHOLDS["max_unsafe_auto_actions"],
                "Risk Owner",
                "Restore fail-closed HITL behavior for escalation scenarios.",
            ),
            self._gate_row(
                "external_calls",
                "Gate remains zero-external-call in local mode",
                observability["external_call_count"],
                DEFAULT_THRESHOLDS["max_external_calls"],
                observability["external_call_count"] <= DEFAULT_THRESHOLDS["max_external_calls"],
                "Platform Owner",
                "Disable optional providers or mark live-provider testing separately.",
            ),
            self._gate_row(
                "review_controls",
                "Trace Eval Lab has no review controls",
                observability["review_control_count"],
                DEFAULT_THRESHOLDS["max_review_controls"],
                observability["review_control_count"] <= DEFAULT_THRESHOLDS["max_review_controls"],
                "Release Owner",
                "Resolve review controls before treating the pack as release-ready.",
            ),
        ]

    def _gate_row(
        self,
        gate_id: str,
        label: str,
        actual: int | float,
        threshold: int | float,
        passed: bool,
        owner: str,
        remediation: str,
    ) -> dict[str, Any]:
        return {
            "gate_id": gate_id,
            "label": label,
            "status": "pass" if passed else "fail",
            "actual": actual,
            "threshold": threshold,
            "owner": owner,
            "remediation": remediation,
        }

    def _summary(
        self,
        scenario_summary: dict[str, Any],
        trace_lab: dict[str, Any],
        gates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        failed = [gate for gate in gates if gate["status"] != "pass"]
        return {
            "scenario_count": scenario_summary["scenario_count"],
            "passed_scenario_count": scenario_summary["passed_scenario_count"],
            "failed_scenario_count": scenario_summary["failed_scenario_count"],
            "classification_accuracy_percent": scenario_summary["classification_accuracy"]["accuracy_percent"],
            "sla_routing_accuracy_percent": scenario_summary["sla_routing"]["accuracy_percent"],
            "approval_pause_accuracy_percent": scenario_summary["approval_pause_coverage"]["accuracy_percent"],
            "observability_score": trace_lab["observability_score"],
            "trace_event_count": trace_lab["summary"]["trace_event_count"],
            "unsafe_auto_action_count": trace_lab["summary"]["unsafe_auto_action_count"],
            "external_call_count": trace_lab["summary"]["external_call_count"],
            "failed_gate_count": len(failed),
            "failed_gate_ids": [gate["gate_id"] for gate in failed],
        }

    def _gate_score(self, gates: list[dict[str, Any]]) -> int:
        if not gates:
            return 0
        passed = len([gate for gate in gates if gate["status"] == "pass"])
        return round((passed / len(gates)) * 100)

    def _run_transparency(
        self,
        scenario_pack: dict[str, Any],
        trace_lab: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "process_mode": "release_regression_gate",
            "scenario_pack_id": scenario_pack["pack_id"],
            "scenario_eval_pack_markdown": scenario_pack["markdown_path"],
            "scenario_eval_pack_json": scenario_pack["json_path"],
            "trace_eval_mode": trace_lab["mode"],
            "trace_run_count": trace_lab["summary"]["run_count"],
            "trace_event_count": trace_lab["summary"]["trace_event_count"],
            "token_count": trace_lab["summary"]["token_count"],
            "estimated_cost_usd": trace_lab["summary"]["estimated_cost_usd"],
            "external_call_count": trace_lab["summary"]["external_call_count"],
        }

    def _owner_actions(self, gates: list[dict[str, Any]]) -> list[dict[str, str]]:
        failed = [gate for gate in gates if gate["status"] != "pass"]
        if not failed:
            return [
                {
                    "owner": "Release Owner",
                    "action": "Attach the regression gate pack to the local release handoff.",
                    "evidence": "All benchmark and review gates passed.",
                }
            ]
        return [
            {
                "owner": gate["owner"],
                "action": gate["remediation"],
                "evidence": gate["gate_id"],
            }
            for gate in failed
        ]

    def _release_decision(self, gate: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": "approve_local_demo_release" if gate["status"] == "pass" else "block_release",
            "status": gate["status"],
            "gate_score": gate["gate_score"],
            "failed_gate_count": gate["summary"]["failed_gate_count"],
            "required_handoff": "Attach scenario and trace eval artifact links before publish.",
        }

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Scenario eval pack reports zero failed scenarios.",
            "Classification, SLA routing, and approval-pause checks meet release thresholds.",
            "Trace Eval Lab score meets the observability threshold.",
            "No unsafe automated escalation actions or external calls are present in local mode.",
            "The pack includes review gates, owner actions, run transparency, and artifact handoffs.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "The gate is deterministic and local; it does not invoke hosted evaluators or CI services.",
            "Scenario execution writes ignored local scenario artifacts as supporting evidence.",
            "Thresholds are static portfolio release thresholds, not organization-specific SLO policy.",
            "Production use should add historical baselines, flaky-test quarantine, and CI trend storage.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        gate = pack["eval_regression_gate"]
        summary = gate["summary"]
        gate_rows = [
            (
                f"| `{item['gate_id']}` | {item['status']} | {item['actual']} | "
                f"{item['threshold']} | {item['owner']} | {item['remediation']} |"
            )
            for item in gate["review_gates"]
        ]
        action_rows = [
            f"- **{item['owner']}**: {item['action']} Evidence: `{item['evidence']}`"
            for item in gate["owner_actions"]
        ]
        command_rows = [f"- `{command}`" for command in pack["local_commands"]]
        criteria_rows = [f"- {item}" for item in pack["acceptance_criteria"]]
        limitation_rows = [f"- {item}" for item in pack["limitations"]]
        handoffs = gate["scenario_artifact_handoff"]
        return "\n".join(
            [
                f"# Eval Regression Gate Pack: {pack['pack_id']}",
                "",
                "## Release Decision",
                f"- Decision: `{pack['release_decision']['decision']}`",
                f"- Status: {gate['status']}",
                f"- Gate score: {gate['gate_score']}",
                f"- Failed gates: {summary['failed_gate_count']}",
                "",
                "## Benchmark Summary",
                f"- Scenarios: {summary['passed_scenario_count']}/{summary['scenario_count']} passed",
                f"- Classification accuracy: {summary['classification_accuracy_percent']}",
                f"- SLA routing accuracy: {summary['sla_routing_accuracy_percent']}",
                f"- Approval pause accuracy: {summary['approval_pause_accuracy_percent']}",
                f"- Observability score: {summary['observability_score']}",
                f"- Trace events: {summary['trace_event_count']}",
                f"- Unsafe auto actions: {summary['unsafe_auto_action_count']}",
                "",
                "## Review Gates",
                "| Gate | Status | Actual | Threshold | Owner | Remediation |",
                "| --- | --- | ---: | ---: | --- | --- |",
                *gate_rows,
                "",
                "## Artifact Handoffs",
                f"- Scenario pack Markdown: `{handoffs['markdown_path']}`",
                f"- Scenario pack JSON: `{handoffs['json_path']}`",
                f"- Trace Eval Lab endpoint: `{gate['trace_eval_handoff']['endpoint']}`",
                "",
                "## Run Transparency",
                f"- Process mode: `{gate['run_transparency']['process_mode']}`",
                f"- Token count: {gate['run_transparency']['token_count']}",
                f"- Estimated cost: ${gate['run_transparency']['estimated_cost_usd']:.6f}",
                f"- External calls: {gate['run_transparency']['external_call_count']}",
                "",
                "## Owner Actions",
                *action_rows,
                "",
                "## Acceptance Criteria",
                *criteria_rows,
                "",
                "## Local Commands",
                *command_rows,
                "",
                "## Limitations",
                *limitation_rows,
                "",
            ]
        )
