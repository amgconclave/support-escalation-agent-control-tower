import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.storage import JsonStateStore
from app.models import AuditEvent, RunRecord
from app.services.audit import AuditService
from app.services.autonomy_governance import TRUSTED_TOOL_NAMES
from app.services.workflow import AgentWorkflowService


TOOL_GOVERNANCE_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "tools/registry|tools/governance-pack|Tool Governance|'
        r'tool_governance_packs|tool manifest|tool registry" app dashboard docs README.md tests scripts'
    ),
]


TOOL_MANIFESTS = [
    {
        "tool_name": "internal_kb.search",
        "display_name": "Internal KB Search",
        "owner": "Support Knowledge Owner",
        "category": "retrieval",
        "risk_tier": "medium",
        "data_exposure": ["ticket subject", "ticket body", "customer tier", "tags"],
        "allowed_actions": ["retrieve cited snippets", "record retry/failure metadata"],
        "approval_required_before": ["customer-visible answer uses retrieved policy guidance"],
        "external_network": False,
        "trusted_by_default": True,
        "failure_mode": "Retry within max_tool_attempts, then route to human review with fallback text.",
    },
    {
        "tool_name": "playbook_recommender",
        "display_name": "Support Playbook Recommender",
        "owner": "Support Operations Lead",
        "category": "decision_support",
        "risk_tier": "low",
        "data_exposure": ["classification", "SLA risk", "local playbook fixtures"],
        "allowed_actions": ["rank local playbooks", "prepare remediation checklist"],
        "approval_required_before": ["owner commitment or customer-facing timeline"],
        "external_network": False,
        "trusted_by_default": True,
        "failure_mode": "Continue with generic operator checklist and mark playbook gap.",
    },
    {
        "tool_name": "fake_zendesk",
        "display_name": "Fake Zendesk Adapter",
        "owner": "Support Platform Owner",
        "category": "support_system",
        "risk_tier": "high",
        "data_exposure": ["customer reply draft", "ticket metadata", "approval decision"],
        "allowed_actions": ["write approved local outbox payload"],
        "approval_required_before": ["customer reply dispatch", "ticket status update"],
        "external_network": False,
        "trusted_by_default": True,
        "failure_mode": "Do not dispatch; preserve outbox/audit evidence for operator retry.",
    },
    {
        "tool_name": "fake_jira",
        "display_name": "Fake Jira Adapter",
        "owner": "Engineering Escalation Owner",
        "category": "engineering_system",
        "risk_tier": "high",
        "data_exposure": ["engineering escalation draft", "reproduction steps", "customer impact"],
        "allowed_actions": ["write approved local engineering ticket payload"],
        "approval_required_before": ["engineering ticket creation", "severity escalation"],
        "external_network": False,
        "trusted_by_default": True,
        "failure_mode": "Block engineering dispatch and keep reviewer handoff in the run state.",
    },
    {
        "tool_name": "fake_slack",
        "display_name": "Fake Slack Adapter",
        "owner": "Incident Commander",
        "category": "notification",
        "risk_tier": "medium",
        "data_exposure": ["severity", "customer impact", "trace and run references"],
        "allowed_actions": ["write approved local Slack alert payload"],
        "approval_required_before": ["incident channel alert", "on-call page escalation"],
        "external_network": False,
        "trusted_by_default": True,
        "failure_mode": "Retain notification payload in local outbox and surface in daily ops brief.",
    },
]


class ToolGovernanceService:
    """Builds a local tool manifest registry and trust review pack."""

    def __init__(
        self,
        store: JsonStateStore,
        workflow: AgentWorkflowService,
        audit: AuditService,
        tool_governance_dir: Path,
    ):
        self.store = store
        self.workflow = workflow
        self.audit = audit
        self.tool_governance_dir = tool_governance_dir

    async def registry(self) -> dict[str, Any]:
        state = await self.store.load()
        runs = [RunRecord(**raw) for raw in state["runs"].values()]
        runs.sort(key=lambda run: str(run.started_at))
        usage = self._usage_summary(runs[-25:])
        manifests = [self._manifest_row(item, usage) for item in TOOL_MANIFESTS]
        unknown_tools = self._unknown_tools(usage)
        controls = self._control_checks(manifests, unknown_tools)
        summary = self._summary(manifests, unknown_tools, controls, usage)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Tool Governance Registry",
            "mode": "local-deterministic-tool-governance",
            "local_mock_only": True,
            "readiness_status": summary["readiness_status"],
            "tool_governance_score": summary["tool_governance_score"],
            "summary": summary,
            "tool_manifests": manifests,
            "unknown_tool_references": unknown_tools,
            "control_checks": controls,
            "marketplace_intake_policy": self._marketplace_intake_policy(),
            "owner_action_plan": self._owner_actions(controls, unknown_tools),
            "repo_radar_patterns": [
                "tool governance",
                "tool trust",
                "marketplace governance",
                "human-in-the-loop",
                "agent cost tracking",
            ],
            "endpoint_list": [
                "GET /tools/registry",
                "POST /tools/governance-pack",
                "GET /governance/autonomy-audit",
                "GET /runs/{run_id}/trace",
                "GET /metrics/agent-performance",
            ],
            "local_commands": TOOL_GOVERNANCE_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self) -> dict[str, Any]:
        registry = await self.registry()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"tool_governance_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.tool_governance_dir / f"{pack_id}.json"
        markdown_path = self.tool_governance_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Tool Governance and Marketplace Trust Pack",
            "tool_registry": registry,
            "approval_matrix": self._approval_matrix(registry["tool_manifests"]),
            "production_acceptance_criteria": self._acceptance_criteria(),
            "artifact_paths": {
                "tool_governance_markdown": str(markdown_path),
                "tool_governance_json": str(json_path),
            },
            "local_commands": TOOL_GOVERNANCE_COMMANDS,
            "limitations": registry["limitations"],
        }
        markdown = self._markdown(pack)
        self.tool_governance_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="tool-governance",
                action="tools.governance_pack_exported",
                resource_type="tool_governance_pack",
                resource_id=pack_id,
                metadata={"markdown_path": str(markdown_path), "json_path": str(json_path)},
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": registry["readiness_status"],
            "tool_governance_score": registry["tool_governance_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    def _usage_summary(self, runs: list[RunRecord]) -> dict[str, Any]:
        counts: Counter[str] = Counter()
        errors: Counter[str] = Counter()
        token_counts: Counter[str] = Counter()
        for run in runs:
            for call in run.state.get("tool_calls", []):
                name = self._tool_name(call)
                counts[name] += 1
                errors[name] += 1 if call.get("status") == "error" else 0
                token_counts[name] += int(call.get("tokens", 0) or 0)
        return {
            "run_count": len(runs),
            "tool_call_counts": dict(counts),
            "tool_error_counts": dict(errors),
            "tool_token_counts": dict(token_counts),
        }

    def _manifest_row(self, manifest: dict[str, Any], usage: dict[str, Any]) -> dict[str, Any]:
        tool_name = manifest["tool_name"]
        call_count = int(usage["tool_call_counts"].get(tool_name, 0))
        error_count = int(usage["tool_error_counts"].get(tool_name, 0))
        tokens = int(usage["tool_token_counts"].get(tool_name, 0))
        controls = self._manifest_controls(manifest)
        return {
            **manifest,
            "registered": tool_name in TRUSTED_TOOL_NAMES,
            "observed_call_count": call_count,
            "observed_error_count": error_count,
            "observed_tokens": tokens,
            "control_status": "pass" if all(item["status"] == "pass" for item in controls) else "review",
            "manifest_controls": controls,
            "rollout_state": "approved_local_only" if manifest["trusted_by_default"] else "intake_required",
        }

    def _manifest_controls(self, manifest: dict[str, Any]) -> list[dict[str, str]]:
        return [
            self._control_row(
                "owner_assigned",
                bool(manifest.get("owner")),
                "Each tool has a named business or platform owner.",
            ),
            self._control_row(
                "risk_tier_declared",
                manifest.get("risk_tier") in {"low", "medium", "high"},
                "Each tool declares low, medium, or high risk.",
            ),
            self._control_row(
                "data_exposure_declared",
                bool(manifest.get("data_exposure")),
                "Each tool lists the support data it can inspect or write.",
            ),
            self._control_row(
                "hitl_boundary_declared",
                bool(manifest.get("approval_required_before")),
                "Each tool declares actions that require human approval first.",
            ),
            self._control_row(
                "failure_mode_declared",
                bool(manifest.get("failure_mode")),
                "Each tool declares retry, fallback, or block behavior.",
            ),
        ]

    def _control_row(self, control_id: str, passed: bool, requirement: str) -> dict[str, str]:
        return {
            "control_id": control_id,
            "status": "pass" if passed else "review",
            "requirement": requirement,
        }

    def _unknown_tools(self, usage: dict[str, Any]) -> list[dict[str, Any]]:
        known = {item["tool_name"] for item in TOOL_MANIFESTS}
        return [
            {
                "tool_name": tool_name,
                "observed_call_count": count,
                "recommended_action": "Block dispatch and require manifest owner, risk tier, data exposure, and failure mode before use.",
            }
            for tool_name, count in usage["tool_call_counts"].items()
            if tool_name not in known
        ]

    def _control_checks(
        self,
        manifests: list[dict[str, Any]],
        unknown_tools: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            self._top_control(
                "all_tools_registered",
                "Observed tool calls map to registered tool manifests",
                not unknown_tools,
                "Platform AI Owner",
                "Add a manifest and owner review before any new tool appears in a run.",
            ),
            self._top_control(
                "trusted_allowlist_aligned",
                "Manifest registry aligns with autonomy governance trusted allowlist",
                {item["tool_name"] for item in manifests} == TRUSTED_TOOL_NAMES,
                "Platform AI Owner",
                "Keep the registry and autonomy trusted tool set synchronized.",
            ),
            self._top_control(
                "high_risk_tools_have_hitl",
                "High-risk tools declare human approval boundaries",
                all(
                    item["approval_required_before"]
                    for item in manifests
                    if item["risk_tier"] == "high"
                ),
                "Support Operations Lead",
                "Require approval gates for customer or engineering-facing high-risk tools.",
            ),
            self._top_control(
                "external_network_disabled",
                "Default tool registry does not call external networks",
                not any(item["external_network"] for item in manifests),
                "Security Owner",
                "Keep live SaaS adapters behind explicit provider activation and policy review.",
            ),
            self._top_control(
                "manifest_controls_complete",
                "Every tool manifest has owner, risk, data, HITL, and failure-mode metadata",
                all(item["control_status"] == "pass" for item in manifests),
                "Support Platform Owner",
                "Complete all manifest controls before marketplace promotion.",
            ),
        ]

    def _top_control(
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
        manifests: list[dict[str, Any]],
        unknown_tools: list[dict[str, Any]],
        controls: list[dict[str, Any]],
        usage: dict[str, Any],
    ) -> dict[str, Any]:
        failed_controls = len([item for item in controls if item["status"] == "fail"])
        high_risk_tools = len([item for item in manifests if item["risk_tier"] == "high"])
        score = max(0, 100 - failed_controls * 20 - len(unknown_tools) * 25)
        return {
            "readiness_status": "blocked" if unknown_tools else "review" if failed_controls else "ready",
            "tool_governance_score": score,
            "registered_tool_count": len(manifests),
            "high_risk_tool_count": high_risk_tools,
            "observed_run_count": usage["run_count"],
            "observed_tool_call_count": sum(usage["tool_call_counts"].values()),
            "observed_tool_error_count": sum(usage["tool_error_counts"].values()),
            "unknown_tool_count": len(unknown_tools),
            "failed_control_count": failed_controls,
        }

    def _marketplace_intake_policy(self) -> dict[str, Any]:
        return {
            "default_decision": "block_until_reviewed",
            "required_manifest_fields": [
                "tool_name",
                "owner",
                "risk_tier",
                "data_exposure",
                "allowed_actions",
                "approval_required_before",
                "failure_mode",
            ],
            "promotion_gates": [
                "contract tests for timeout, retry, token/cost accounting, and redaction",
                "policy guardrail simulation for customer and engineering-facing actions",
                "data residency review for payload fields",
                "human approval boundary before any external dispatch",
            ],
            "local_default": "Only fake/local tools are approved in the default portfolio runtime.",
        }

    def _owner_actions(
        self,
        controls: list[dict[str, Any]],
        unknown_tools: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        actions = [
            {
                "owner": control["owner"],
                "priority": "high",
                "action": control["remediation"],
                "evidence": control["control_id"],
            }
            for control in controls
            if control["status"] == "fail"
        ]
        actions.extend(
            {
                "owner": "Platform AI Owner",
                "priority": "critical",
                "action": item["recommended_action"],
                "evidence": item["tool_name"],
            }
            for item in unknown_tools
        )
        return actions or [
            {
                "owner": "Platform AI Owner",
                "priority": "normal",
                "action": "Review the tool registry before adding live SaaS or marketplace tools.",
                "evidence": "all_tool_controls_passed",
            }
        ]

    def _approval_matrix(self, manifests: list[dict[str, Any]]) -> list[dict[str, str]]:
        return [
            {
                "tool_name": item["tool_name"],
                "risk_tier": item["risk_tier"],
                "owner": item["owner"],
                "approval_required_before": "; ".join(item["approval_required_before"]),
                "rollout_state": item["rollout_state"],
            }
            for item in manifests
        ]

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Every approved tool has an owner, risk tier, data exposure summary, HITL boundary, and failure mode.",
            "Observed tool calls in run state map to known manifests and the trusted allowlist.",
            "High-risk support-system and engineering-system tools require approval before dispatch.",
            "Default portfolio runtime remains local/mock and does not call external SaaS or LLM providers.",
            "New tools are blocked until contract tests, policy simulation, and data review are complete.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "The registry is deterministic local metadata, not a remote signed marketplace.",
            "It audits observed local tool-call names and fake adapters only.",
            "It does not call Zendesk, Jira, Slack, Azure, OpenAI, GitHub, or external tool registries.",
            "Production rollout would need signed manifests, RBAC, tenant scoping, and deployment approvals.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        registry = pack["tool_registry"]
        summary = registry["summary"]
        manifest_rows = [
            (
                f"| `{item['tool_name']}` | {item['owner']} | {item['risk_tier']} | "
                f"{item['observed_call_count']} | {item['control_status']} |"
            )
            for item in registry["tool_manifests"]
        ]
        control_rows = [
            f"| `{item['control_id']}` | {item['status']} | {item['owner']} | {item['remediation']} |"
            for item in registry["control_checks"]
        ]
        approval_rows = [
            (
                f"| `{item['tool_name']}` | {item['risk_tier']} | {item['owner']} | "
                f"{item['approval_required_before']} | {item['rollout_state']} |"
            )
            for item in pack["approval_matrix"]
        ]
        unknown_rows = [
            f"| `{item['tool_name']}` | {item['observed_call_count']} | {item['recommended_action']} |"
            for item in registry["unknown_tool_references"]
        ] or ["| none | 0 | no action |"]
        commands = [f"- `{command}`" for command in pack["local_commands"]]
        criteria = [f"- {item}" for item in pack["production_acceptance_criteria"]]
        limitations = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Tool Governance and Marketplace Trust Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: {registry['readiness_status']}",
                f"- Score: {registry['tool_governance_score']}",
                f"- Registered tools: {summary['registered_tool_count']}",
                f"- Observed tool calls: {summary['observed_tool_call_count']}",
                f"- Unknown tools: {summary['unknown_tool_count']}",
                "",
                "## Tool Manifests",
                "| Tool | Owner | Risk | Calls | Controls |",
                "| --- | --- | --- | ---: | --- |",
                *manifest_rows,
                "",
                "## Control Checks",
                "| Control | Status | Owner | Remediation |",
                "| --- | --- | --- | --- |",
                *control_rows,
                "",
                "## Approval Matrix",
                "| Tool | Risk | Owner | Approval Required Before | Rollout |",
                "| --- | --- | --- | --- | --- |",
                *approval_rows,
                "",
                "## Unknown Tool References",
                "| Tool | Calls | Action |",
                "| --- | ---: | --- |",
                *unknown_rows,
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

    def _tool_name(self, call: dict[str, Any]) -> str:
        return str(call.get("tool") or call.get("name") or "unknown")
