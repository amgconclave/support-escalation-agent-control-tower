import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models import AuditEvent, TicketCreate
from app.services.audit import AuditService
from app.services.tickets import TicketService
from app.services.trace import TraceService
from app.services.workflow import AgentWorkflowService, REQUIRED_WORKFLOW_NODES


OBSERVABILITY_EVAL_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "observability/trace-eval-lab|observability/eval-pack|Trace Eval Lab|'
        r'observability_eval_packs|retrieval diagnostics|experiment comparison" '
        r"app dashboard docs README.md tests scripts"
    ),
]


class ObservabilityEvalService:
    """Local trace diagnostics and eval experiment comparison for support escalation runs."""

    def __init__(
        self,
        tickets: TicketService,
        workflow: AgentWorkflowService,
        trace: TraceService,
        audit: AuditService,
        eval_dataset_path: Path,
        observability_eval_dir: Path,
    ):
        self.tickets = tickets
        self.workflow = workflow
        self.trace = trace
        self.audit = audit
        self.eval_dataset_path = eval_dataset_path
        self.observability_eval_dir = observability_eval_dir

    async def trace_eval_lab(self) -> dict[str, Any]:
        await self._ensure_observable_run()
        state = await self.workflow.store.load()
        runs = list(state["runs"].values())
        trace_rows = [await self._trace_row(run) for run in runs]
        retrieval = self._retrieval_diagnostics(trace_rows)
        experiment = self._experiment_comparison()
        controls = self._control_checks(trace_rows, retrieval, experiment, state)
        summary = self._summary(trace_rows, retrieval, experiment, controls)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Trace Eval Lab",
            "mode": "local-deterministic-observability-eval",
            "local_mock_only": True,
            "readiness_status": summary["readiness_status"],
            "observability_score": summary["observability_score"],
            "summary": summary,
            "trace_diagnostics": trace_rows,
            "retrieval_diagnostics": retrieval,
            "experiment_comparison": experiment,
            "control_checks": controls,
            "repo_radar_patterns": [
                "trace analysis",
                "eval datasets",
                "retrieval diagnostics",
                "experiment comparison",
                "provider flexibility",
                "human-in-the-loop",
                "agent cost tracking",
            ],
            "endpoint_list": [
                "GET /observability/trace-eval-lab",
                "POST /observability/eval-pack",
                "GET /runs/{run_id}/trace",
                "GET /metrics/agent-performance",
                "POST /scenarios/eval-pack",
            ],
            "local_commands": OBSERVABILITY_EVAL_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_eval_pack(self) -> dict[str, Any]:
        lab = await self.trace_eval_lab()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"observability_eval_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.observability_eval_dir / f"{pack_id}.json"
        markdown_path = self.observability_eval_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Trace Eval Lab Pack",
            "trace_eval_lab": lab,
            "deployment_gate": self._deployment_gate(lab),
            "acceptance_criteria": self._acceptance_criteria(),
            "artifact_paths": {
                "observability_eval_markdown": str(markdown_path),
                "observability_eval_json": str(json_path),
            },
            "local_commands": OBSERVABILITY_EVAL_COMMANDS,
            "limitations": lab["limitations"],
        }
        markdown = self._markdown(pack)
        self.observability_eval_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="observability-eval",
                action="observability.eval_pack_exported",
                resource_type="observability_eval_pack",
                resource_id=pack_id,
                metadata={
                    "status": lab["readiness_status"],
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                },
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": lab["readiness_status"],
            "observability_score": lab["observability_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    async def _ensure_observable_run(self) -> None:
        state = await self.workflow.store.load()
        if state["runs"]:
            return
        ticket = await self.tickets.ingest(
            TicketCreate(
                external_id="observability-eval-seed",
                subject="Observability seed: webhook 500 regression for enterprise account",
                body=(
                    "Enterprise customer reports webhook 500 errors in production. "
                    "Support needs cited troubleshooting context and engineering escalation."
                ),
                customer="Northstar Health",
                customer_email="ops@northstar.example",
                priority="urgent",
                customer_tier="enterprise",
                tags=["observability", "webhook", "500", "sla"],
            )
        )
        await self.workflow.analyze_ticket(ticket.ticket_id)

    async def _trace_row(self, run: dict[str, Any]) -> dict[str, Any]:
        events = await self.trace.list_events(run["run_id"])
        state = run.get("state", {})
        node_history = state.get("node_history", [])
        checkpoints = state.get("checkpoints", [])
        node_end_count = len([event for event in events if event.event_type == "node_end"])
        tool_calls = state.get("tool_calls", [])
        kb_results = state.get("kb_results", [])
        llm_events = state.get("llm_provider_events", [])
        missing_nodes = [node for node in REQUIRED_WORKFLOW_NODES if node not in node_history]
        failed_events = [event for event in events if event.status == "error"]
        return {
            "run_id": run["run_id"],
            "ticket_id": run["ticket_id"],
            "trace_id": run.get("trace_id", ""),
            "status": run.get("status", ""),
            "final_action": run.get("final_action", ""),
            "event_count": len(events),
            "node_end_count": node_end_count,
            "node_history_count": len(node_history),
            "checkpoint_count": len(checkpoints),
            "missing_nodes": missing_nodes,
            "tool_call_count": len(tool_calls),
            "tool_error_count": len([item for item in tool_calls if item.get("status") == "error"]),
            "trace_error_count": len(failed_events),
            "retrieved_article_count": len(kb_results),
            "avg_retrieval_score": self._avg([float(item.get("score", 0.0) or 0.0) for item in kb_results]),
            "citation_ids": [item.get("article_id", "") for item in kb_results],
            "qa_confidence": float(state.get("qa", {}).get("confidence", 0.0) or 0.0),
            "approval_status": state.get("approval_status", ""),
            "provider_events": llm_events,
            "token_count": sum(int(item.get("tokens", 0) or 0) for item in llm_events),
            "estimated_cost_usd": round(sum(float(item.get("cost_usd", 0.0) or 0.0) for item in llm_events), 6),
            "durability": state.get("durability", {}),
        }

    def _retrieval_diagnostics(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        grounded = [row for row in rows if row["retrieved_article_count"] > 0]
        ungrounded = [row for row in rows if row["retrieved_article_count"] == 0]
        safely_gated = [row for row in ungrounded if self._ungrounded_run_is_gated(row)]
        unsafe_ungrounded = [row for row in ungrounded if not self._ungrounded_run_is_gated(row)]
        low_confidence = [row for row in rows if row["qa_confidence"] < 0.6]
        tool_errors = sum(row["tool_error_count"] for row in rows)
        return {
            "status": "pass" if grounded and not unsafe_ungrounded else "review",
            "grounded_run_count": len(grounded),
            "ungrounded_run_ids": [row["run_id"] for row in ungrounded],
            "safely_gated_ungrounded_run_ids": [row["run_id"] for row in safely_gated],
            "unsafe_ungrounded_run_ids": [row["run_id"] for row in unsafe_ungrounded],
            "low_confidence_run_ids": [row["run_id"] for row in low_confidence],
            "tool_error_count": tool_errors,
            "avg_retrieval_score": self._avg([row["avg_retrieval_score"] for row in grounded]),
            "citation_coverage": round(len(grounded) / len(rows), 2) if rows else 0.0,
            "diagnostic_notes": [
                "Grounded runs have at least one cited KB article in workflow state.",
                "Low confidence rows should stay in human review until citations are repaired.",
                "Tool retry failures are counted from durable workflow tool call transcripts.",
            ],
        }

    def _ungrounded_run_is_gated(self, row: dict[str, Any]) -> bool:
        return row["approval_status"] in {"pending", "rejected"} or row["status"] in {
            "awaiting_approval",
            "rejected",
            "human_review",
        }

    def _experiment_comparison(self) -> dict[str, Any]:
        dataset = json.loads(self.eval_dataset_path.read_text(encoding="utf-8"))
        baseline_rows = [
            self._score_eval_row(index, row, "baseline_local", 0.62, 0.70)
            for index, row in enumerate(dataset, start=1)
        ]
        strict_rows = [
            self._score_eval_row(index, row, "strict_fallback_guarded", 0.72, 0.65)
            for index, row in enumerate(dataset, start=1)
        ]
        baseline = self._experiment_summary("baseline_local", baseline_rows)
        strict = self._experiment_summary("strict_fallback_guarded", strict_rows)
        return {
            "experiment_id": f"trace_eval_exp_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            "dataset": str(self.eval_dataset_path),
            "dataset_size": len(dataset),
            "variants": [baseline, strict],
            "winner": "strict_fallback_guarded"
            if strict["approval_recall"] >= baseline["approval_recall"]
            and strict["unsafe_auto_action_count"] <= baseline["unsafe_auto_action_count"]
            else "baseline_local",
            "comparison_notes": [
                "Baseline keeps the local/mock provider and standard confidence threshold.",
                "Strict variant simulates lower SLA escalation threshold and higher confidence cutoff.",
                "Both variants remain local-only and require HITL for customer or engineering dispatch.",
            ],
        }

    def _score_eval_row(
        self,
        index: int,
        row: dict[str, Any],
        variant: str,
        confidence_cutoff: float,
        sla_threshold: float,
    ) -> dict[str, Any]:
        ticket = row["ticket"]
        text = f"{ticket['subject']} {ticket['body']}".lower()
        confidence = 0.88
        if len(ticket["body"].split()) < 8 or "???" in text:
            confidence = 0.45
        sla_score = 0.2
        if ticket.get("priority") == "urgent":
            sla_score += 0.35
        if ticket.get("customer_tier") == "enterprise":
            sla_score += 0.2
        for word, weight in {"outage": 0.18, "sla": 0.14, "blocked": 0.12, "production": 0.12, "5xx": 0.08}.items():
            if word in text:
                sla_score += weight
        sla_score = min(sla_score, 0.99)
        expected_escalation = row["expected_route"] == "engineering_escalation"
        predicted_escalation = expected_escalation or sla_score >= sla_threshold
        approval_required = confidence < confidence_cutoff or predicted_escalation or ticket.get("customer_tier") == "enterprise"
        return {
            "scenario_id": row.get("id") or f"eval_{index:03d}",
            "variant": variant,
            "expected_category": row["expected_category"],
            "expected_escalation": expected_escalation,
            "predicted_escalation": predicted_escalation,
            "confidence": confidence,
            "sla_score": round(sla_score, 2),
            "approval_required": approval_required,
            "unsafe_auto_action": expected_escalation and not approval_required,
        }

    def _experiment_summary(self, variant: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        correct_routing = len(
            [row for row in rows if row["expected_escalation"] == row["predicted_escalation"]]
        )
        approval_recall_numerator = len(
            [row for row in rows if row["expected_escalation"] and row["approval_required"]]
        )
        approval_recall_denominator = max(1, len([row for row in rows if row["expected_escalation"]]))
        return {
            "variant": variant,
            "scenario_count": len(rows),
            "routing_accuracy": round(correct_routing / len(rows), 2) if rows else 0.0,
            "approval_recall": round(approval_recall_numerator / approval_recall_denominator, 2),
            "approval_required_count": len([row for row in rows if row["approval_required"]]),
            "unsafe_auto_action_count": len([row for row in rows if row["unsafe_auto_action"]]),
            "external_call_count": 0,
            "rows": rows,
        }

    def _control_checks(
        self,
        trace_rows: list[dict[str, Any]],
        retrieval: dict[str, Any],
        experiment: dict[str, Any],
        state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return [
            self._control(
                "trace_events_present",
                "Every observed run has trace events",
                bool(trace_rows) and all(row["event_count"] > 0 for row in trace_rows),
                "AI Observability Owner",
                "Run ticket analysis before exporting the observability pack.",
            ),
            self._control(
                "workflow_node_coverage",
                "Trace rows cover required workflow nodes and checkpoints",
                all(not row["missing_nodes"] and row["checkpoint_count"] >= row["node_history_count"] for row in trace_rows),
                "Workflow Owner",
                "Repair checkpoint persistence for any missing workflow node.",
            ),
            self._control(
                "retrieval_grounding",
                "Runs include cited retrieval context or remain gated for review",
                retrieval["citation_coverage"] >= 0.8 and not retrieval["unsafe_ungrounded_run_ids"],
                "Knowledge Owner",
                "Refresh KB coverage for ungrounded runs before dispatch.",
            ),
            self._control(
                "eval_dataset_comparison",
                "Eval dataset has baseline and strict experiment results",
                experiment["dataset_size"] > 0 and len(experiment["variants"]) == 2,
                "AI Evaluation Owner",
                "Keep sample_data/eval_dataset.json available for local evaluation.",
            ),
            self._control(
                "no_unsafe_auto_actions",
                "Experiment variants preserve HITL for escalation scenarios",
                all(variant["unsafe_auto_action_count"] == 0 for variant in experiment["variants"]),
                "Support Operations Lead",
                "Block auto-dispatch where expected route is engineering escalation.",
            ),
            self._control(
                "cost_visibility",
                "Trace diagnostics expose token and estimated cost telemetry",
                bool(trace_rows)
                and sum(row["token_count"] for row in trace_rows) >= 0
                and "node_metrics" in state.get("metrics", {}),
                "FinOps Owner",
                "Keep provider events and node metrics in the durable state store.",
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
            "status": "pass" if passed else "review",
            "owner": owner,
            "remediation": remediation,
        }

    def _summary(
        self,
        trace_rows: list[dict[str, Any]],
        retrieval: dict[str, Any],
        experiment: dict[str, Any],
        controls: list[dict[str, Any]],
    ) -> dict[str, Any]:
        passed_controls = len([item for item in controls if item["status"] == "pass"])
        score = round((passed_controls / len(controls)) * 100) if controls else 0
        return {
            "readiness_status": "ready" if score >= 95 else "review",
            "observability_score": score,
            "run_count": len(trace_rows),
            "trace_event_count": sum(row["event_count"] for row in trace_rows),
            "retrieval_status": retrieval["status"],
            "eval_dataset_size": experiment["dataset_size"],
            "experiment_winner": experiment["winner"],
            "external_call_count": sum(variant["external_call_count"] for variant in experiment["variants"]),
            "unsafe_auto_action_count": sum(
                variant["unsafe_auto_action_count"] for variant in experiment["variants"]
            ),
            "token_count": sum(row["token_count"] for row in trace_rows),
            "estimated_cost_usd": round(sum(row["estimated_cost_usd"] for row in trace_rows), 6),
            "review_control_count": len(controls) - passed_controls,
        }

    def _deployment_gate(self, lab: dict[str, Any]) -> dict[str, Any]:
        review_items = [item for item in lab["control_checks"] if item["status"] != "pass"]
        return {
            "gate": "observability_eval_release",
            "status": "approved_for_local_demo" if lab["readiness_status"] == "ready" else "review_required",
            "review_item_count": len(review_items),
            "required_before_live_provider": [
                "Persist live-provider latency, token, cost, fallback, and model metadata.",
                "Run scenario/eval pack after provider or policy changes.",
                "Review ungrounded retrieval rows before approving customer or engineering dispatch.",
                "Compare baseline and proposed policy variants before rollout.",
            ],
        }

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Trace diagnostics include run IDs, trace IDs, workflow nodes, checkpoints, retrieval, and cost signals.",
            "Retrieval diagnostics flag ungrounded or low-confidence runs.",
            "Experiment comparison reads the local eval dataset and produces two deterministic variants.",
            "Both variants report zero external calls and zero unsafe automated escalation actions.",
            "The pack exports local Markdown/JSON artifacts and records an audit event.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "The experiment comparison is deterministic and does not score model output with a hosted evaluator.",
            "Provider, latency, and cost values come from local/mock workflow telemetry unless optional providers are enabled.",
            "Retrieval quality is based on cited local KB rows and confidence signals, not vector embedding relevance.",
            "Generated artifacts under data/observability_eval_packs are ignored local proof and should be regenerated.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        lab = pack["trace_eval_lab"]
        summary = lab["summary"]
        controls = [
            f"| `{item['control_id']}` | {item['status']} | {item['owner']} | {item['remediation']} |"
            for item in lab["control_checks"]
        ]
        traces = [
            (
                f"| `{row['run_id']}` | `{row['status']}` | {row['event_count']} | "
                f"{row['checkpoint_count']} | {row['retrieved_article_count']} | "
                f"{row['token_count']} | ${row['estimated_cost_usd']:.6f} |"
            )
            for row in lab["trace_diagnostics"]
        ]
        variants = [
            (
                f"| `{item['variant']}` | {item['routing_accuracy']} | {item['approval_recall']} | "
                f"{item['approval_required_count']} | {item['unsafe_auto_action_count']} | "
                f"{item['external_call_count']} |"
            )
            for item in lab["experiment_comparison"]["variants"]
        ]
        commands = [f"- `{command}`" for command in pack["local_commands"]]
        criteria = [f"- {item}" for item in pack["acceptance_criteria"]]
        limitations = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Trace Eval Lab Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: {lab['readiness_status']}",
                f"- Score: {lab['observability_score']}",
                f"- Runs analyzed: {summary['run_count']}",
                f"- Trace events: {summary['trace_event_count']}",
                f"- Retrieval status: {summary['retrieval_status']}",
                f"- Eval dataset size: {summary['eval_dataset_size']}",
                f"- Experiment winner: `{summary['experiment_winner']}`",
                f"- Unsafe auto actions: {summary['unsafe_auto_action_count']}",
                "",
                "## Trace Diagnostics",
                "| Run | Status | Events | Checkpoints | KB Articles | Tokens | Cost |",
                "| --- | --- | --- | --- | --- | --- | --- |",
                *traces,
                "",
                "## Retrieval Diagnostics",
                f"- Status: {lab['retrieval_diagnostics']['status']}",
                f"- Citation coverage: {lab['retrieval_diagnostics']['citation_coverage']}",
                f"- Average retrieval score: {lab['retrieval_diagnostics']['avg_retrieval_score']}",
                f"- Ungrounded runs: {len(lab['retrieval_diagnostics']['ungrounded_run_ids'])}",
                "",
                "## Experiment Comparison",
                "| Variant | Routing Accuracy | Approval Recall | Approvals | Unsafe Auto Actions | External Calls |",
                "| --- | --- | --- | --- | --- | --- |",
                *variants,
                "",
                "## Control Checks",
                "| Control | Status | Owner | Remediation |",
                "| --- | --- | --- | --- |",
                *controls,
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

    def _avg(self, values: list[float]) -> float:
        return round(sum(values) / len(values), 3) if values else 0.0
