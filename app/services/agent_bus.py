import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models import AuditEvent
from app.services.audit import AuditService


DEFAULT_SUPERVISOR_BUS_ROOT = Path(r"C:\Users\Devan\Documents\fixing github\codex-supervisor\agent-bus")

AGENT_BUS_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "ops/agent-bus-audit|ops/agent-bus-pack|Agent Bus|'
        r'agent_bus_packs|agent communication bus|handoff ledger" app dashboard docs README.md tests scripts'
    ),
]

BUS_AGENTS = [
    {
        "agent_id": "conductor",
        "role": "Supervisor",
        "responsibilities": ["schedule", "prioritize", "verify", "publish", "handoff"],
        "expected_inbox": r"inbox\conductor.jsonl",
        "guardrail": "Coordinates work but does not mutate repo files directly through this audit.",
    },
    {
        "agent_id": "codex_cli_worker",
        "role": "CLI Worker",
        "responsibilities": ["edit_repo", "run_tests", "summarize_changes"],
        "expected_inbox": r"inbox\codex_cli_worker.jsonl",
        "guardrail": "Must keep external providers optional and avoid destructive git actions.",
    },
    {
        "agent_id": "verifier",
        "role": "Local Tooling Verifier",
        "responsibilities": ["run_verification", "inspect_reports", "gate_publish"],
        "expected_inbox": r"inbox\verifier.jsonl",
        "guardrail": "Can gate publish readiness but cannot stage, push, or call GitHub APIs.",
    },
    {
        "agent_id": "repo_radar",
        "role": "Research Agent",
        "responsibilities": ["suggest_patterns", "prevent_duplicate_features", "score_relevance"],
        "expected_inbox": r"inbox\repo_radar.jsonl",
        "guardrail": "Provides architecture inspiration only; no copied external code.",
    },
    {
        "agent_id": "codex_ui_bridge",
        "role": "Operator Queue",
        "responsibilities": ["prepare_ui_continuation", "queue_human_visible_message", "track_session_context"],
        "expected_inbox": r"inbox\codex_ui_bridge.jsonl",
        "guardrail": "Writes queue artifacts instead of automating the Codex desktop UI.",
    },
]


class AgentBusCoordinationService:
    """Audits local multi-agent handoff JSONL files without mutating the bus."""

    def __init__(self, audit: AuditService, agent_bus_dir: Path, bus_root: Path | None = None):
        self.audit = audit
        self.agent_bus_dir = agent_bus_dir
        self.configured_bus_root = bus_root
        self.repo_root = Path(__file__).resolve().parents[2]

    async def audit_bus(self) -> dict[str, Any]:
        bus_root = self._resolve_bus_root()
        messages, file_rows = self._read_bus_messages(bus_root)
        summary = self._summary(messages, file_rows, bus_root)
        control_gates = self._control_gates(summary, messages, file_rows)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Agent Communication Bus Audit",
            "mode": "local-readonly-agent-bus-audit",
            "local_mock_only": True,
            "bus_root": str(bus_root),
            "bus_root_exists": bus_root.exists(),
            "readiness_status": summary["readiness_status"],
            "coordination_score": summary["coordination_score"],
            "summary": summary,
            "agent_registry": BUS_AGENTS,
            "message_files": file_rows,
            "message_routes": self._message_routes(messages),
            "handoff_ledger": self._handoff_ledger(messages),
            "control_gates": control_gates,
            "operator_queue": self._operator_queue(control_gates, file_rows),
            "recent_messages": self._recent_messages(messages),
            "repo_radar_patterns": [
                "agent roles",
                "task delegation",
                "review gates",
                "run transparency",
                "artifact handoffs",
                "task sandbox",
            ],
            "endpoint_list": ["GET /ops/agent-bus-audit", "POST /ops/agent-bus-pack"],
            "local_commands": AGENT_BUS_COMMANDS,
            "limitations": self._limitations(bus_root),
        }

    async def export_pack(self) -> dict[str, Any]:
        bus_audit = await self.audit_bus()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"agent_bus_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.agent_bus_dir / f"{pack_id}.json"
        markdown_path = self.agent_bus_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Agent Coordination Bus Pack",
            "bus_audit": bus_audit,
            "review_gate_summary": self._review_gate_summary(bus_audit["control_gates"]),
            "handoff_acceptance_criteria": self._acceptance_criteria(),
            "artifact_paths": {
                "agent_bus_markdown": str(markdown_path),
                "agent_bus_json": str(json_path),
            },
            "local_commands": AGENT_BUS_COMMANDS,
            "limitations": bus_audit["limitations"],
        }
        markdown = self._markdown(pack)
        self.agent_bus_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="agent-bus-auditor",
                action="ops.agent_bus_pack_exported",
                resource_type="agent_bus_pack",
                resource_id=pack_id,
                metadata={"markdown_path": str(markdown_path), "json_path": str(json_path)},
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": bus_audit["readiness_status"],
            "coordination_score": bus_audit["coordination_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    def _resolve_bus_root(self) -> Path:
        if self.configured_bus_root and self.configured_bus_root.exists():
            return self.configured_bus_root
        if DEFAULT_SUPERVISOR_BUS_ROOT.exists():
            return DEFAULT_SUPERVISOR_BUS_ROOT
        return self.configured_bus_root or self.agent_bus_dir.parent / "agent_bus_runtime"

    def _read_bus_messages(self, bus_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        messages: list[dict[str, Any]] = []
        file_rows = []
        for agent in BUS_AGENTS:
            for stream in ("inbox", "outbox"):
                path = bus_root / stream / f"{agent['agent_id']}.jsonl"
                parsed, malformed = self._read_jsonl(path)
                messages.extend(parsed)
                file_rows.append(
                    {
                        "agent_id": agent["agent_id"],
                        "stream": stream,
                        "path": str(path),
                        "exists": path.exists(),
                        "message_count": len(parsed),
                        "malformed_count": malformed,
                        "latest_time": self._latest_time(parsed),
                    }
                )
        messages.sort(key=lambda item: str(item.get("time") or item.get("timestamp") or ""))
        return messages, file_rows

    def _read_jsonl(self, path: Path) -> tuple[list[dict[str, Any]], int]:
        if not path.exists() or not path.is_file():
            return [], 0
        messages = []
        malformed = 0
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-250:]
        for index, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(payload, dict):
                payload["_source_path"] = str(path)
                payload["_line"] = index
                messages.append(payload)
            else:
                malformed += 1
        return messages, malformed

    def _summary(
        self,
        messages: list[dict[str, Any]],
        file_rows: list[dict[str, Any]],
        bus_root: Path,
    ) -> dict[str, Any]:
        malformed_count = sum(row["malformed_count"] for row in file_rows)
        existing_files = len([row for row in file_rows if row["exists"]])
        inbox_files = [row for row in file_rows if row["stream"] == "inbox"]
        inbox_coverage = len([row for row in inbox_files if row["exists"]])
        latest_time = self._latest_time(messages)
        gates_penalty = 0
        if not bus_root.exists():
            gates_penalty += 15
        if malformed_count:
            gates_penalty += 25
        if inbox_coverage and inbox_coverage < len(BUS_AGENTS):
            gates_penalty += 10
        score = max(0, 100 - gates_penalty)
        if not bus_root.exists():
            status = "ready_no_bus_files"
        elif malformed_count:
            status = "review_malformed_messages"
        elif not messages:
            status = "ready_no_messages"
        else:
            status = "ready"
        return {
            "readiness_status": status,
            "coordination_score": score,
            "registered_agent_count": len(BUS_AGENTS),
            "message_file_count": len(file_rows),
            "existing_message_file_count": existing_files,
            "inbox_coverage_count": inbox_coverage,
            "message_count": len(messages),
            "malformed_message_count": malformed_count,
            "unique_sender_count": len({item.get("sender") for item in messages if item.get("sender")}),
            "unique_recipient_count": len({item.get("recipient") for item in messages if item.get("recipient")}),
            "latest_message_time": latest_time,
            "external_call_count": 0,
        }

    def _message_routes(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        counts: Counter[tuple[str, str, str]] = Counter()
        for message in messages:
            sender = str(message.get("sender") or "unknown")
            recipient = str(message.get("recipient") or "unknown")
            message_type = str(message.get("type") or "message")
            counts[(sender, recipient, message_type)] += 1
        return [
            {"sender": sender, "recipient": recipient, "type": message_type, "message_count": count}
            for (sender, recipient, message_type), count in sorted(counts.items())
        ]

    def _handoff_ledger(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        required = [
            ("conductor", "codex_cli_worker", "work_assignment", "Worker has a supervisor task to execute."),
            ("codex_cli_worker", "conductor", "completion", "Worker reports implementation and verification outcome."),
            ("codex_cli_worker", "verifier", "verification_request", "Verifier can independently gate publish readiness."),
            ("repo_radar", "codex_cli_worker", "pattern_guidance", "Architecture inspiration is visible before implementation."),
            ("codex_cli_worker", "codex_ui_bridge", "ui_continuation", "Human-visible UI continuation is queued instead of desktop automation."),
        ]
        rows = []
        for sender, recipient, handoff_type, purpose in required:
            matching = [
                message
                for message in messages
                if message.get("sender") == sender and message.get("recipient") == recipient
            ]
            rows.append(
                {
                    "handoff_type": handoff_type,
                    "sender": sender,
                    "recipient": recipient,
                    "purpose": purpose,
                    "observed": bool(matching),
                    "message_count": len(matching),
                    "latest_time": self._latest_time(matching),
                }
            )
        return rows

    def _control_gates(
        self,
        summary: dict[str, Any],
        messages: list[dict[str, Any]],
        file_rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        known_agents = {agent["agent_id"] for agent in BUS_AGENTS}
        unknown_recipients = sorted(
            {
                str(message.get("recipient"))
                for message in messages
                if message.get("recipient") and message.get("recipient") not in known_agents
            }
        )
        return [
            self._gate(
                "registered_agent_gate",
                "Operations Commander",
                summary["registered_agent_count"] == 5,
                "The bus registry covers conductor, worker, verifier, repo radar, and UI bridge roles.",
            ),
            self._gate(
                "readonly_sandbox_gate",
                "Platform AI Owner",
                True,
                "The audit reads JSONL files and writes only an ignored local reviewer pack.",
            ),
            self._gate(
                "jsonl_integrity_gate",
                "Verifier",
                summary["malformed_message_count"] == 0,
                "Message files should parse as JSON Lines with no malformed records.",
            ),
            self._gate(
                "known_recipient_gate",
                "Conductor",
                not unknown_recipients,
                "Messages should target registered local bus recipients.",
                {"unknown_recipients": unknown_recipients},
            ),
            self._gate(
                "ui_boundary_gate",
                "Operator Queue",
                True,
                "UI continuation is represented as queue artifacts; the service does not automate the desktop UI.",
            ),
            self._gate(
                "external_call_boundary_gate",
                "Security Owner",
                summary["external_call_count"] == 0,
                "Agent-bus audit must not call GitHub, Azure, OpenAI, Slack, Jira, Zendesk, or network providers.",
            ),
        ]

    def _gate(
        self,
        gate_id: str,
        owner_role: str,
        passed: bool,
        requirement: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "gate_id": gate_id,
            "owner_role": owner_role,
            "status": "pass" if passed else "review",
            "requirement": requirement,
            "metadata": metadata or {},
        }

    def _operator_queue(
        self,
        gates: list[dict[str, Any]],
        file_rows: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        actions = [
            {
                "owner": gate["owner_role"],
                "priority": "high",
                "action": f"Review bus control gate `{gate['gate_id']}`.",
                "evidence": gate["requirement"],
            }
            for gate in gates
            if gate["status"] != "pass"
        ]
        missing_inboxes = [row for row in file_rows if row["stream"] == "inbox" and not row["exists"]]
        actions.extend(
            {
                "owner": "Conductor",
                "priority": "normal",
                "action": f"Create or document missing inbox for `{row['agent_id']}` if bus coordination is enabled.",
                "evidence": row["path"],
            }
            for row in missing_inboxes
        )
        return actions or [
            {
                "owner": "Conductor",
                "priority": "normal",
                "action": "Continue using JSONL handoffs and export this pack after major worker runs.",
                "evidence": "all_agent_bus_gates_passed",
            }
        ]

    def _recent_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for message in list(reversed(messages))[:12]:
            body = message.get("body", "")
            rows.append(
                {
                    "time": str(message.get("time") or message.get("timestamp") or ""),
                    "sender": str(message.get("sender") or ""),
                    "recipient": str(message.get("recipient") or ""),
                    "type": str(message.get("type") or ""),
                    "subject": str(message.get("subject") or "")[:160],
                    "body_preview": str(body)[:220],
                    "source_path": str(message.get("_source_path") or ""),
                }
            )
        return rows

    def _latest_time(self, messages: list[dict[str, Any]]) -> str:
        values = [str(item.get("time") or item.get("timestamp") or "") for item in messages]
        values = [value for value in values if value]
        return max(values) if values else ""

    def _review_gate_summary(self, gates: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "pass_count": len([gate for gate in gates if gate["status"] == "pass"]),
            "review_count": len([gate for gate in gates if gate["status"] != "pass"]),
        }

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Registered bus roles match conductor, worker, verifier, repo radar, and UI bridge responsibilities.",
            "JSONL message files parse cleanly and recent handoffs are visible without external services.",
            "Verifier and UI bridge handoffs are represented as queue messages or documented gaps.",
            "The audit remains read-only against bus files and writes only ignored local proof artifacts.",
            "No GitHub, Azure, OpenAI, Zendesk, Jira, Slack, browser, desktop, or network automation occurs.",
        ]

    def _limitations(self, bus_root: Path) -> list[str]:
        return [
            "The audit reads local JSONL files only when they exist; missing bus folders are reported as a local review condition.",
            f"Resolved bus root is `{bus_root}`; set a different root in service construction for another supervisor layout.",
            "Message bodies are summarized with short previews and are not treated as a source of truth for repo state.",
            "This service does not send, route, delete, or acknowledge bus messages.",
            "Production use would need identity, leases, retention policy, signing, and queue backpressure controls.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        audit = pack["bus_audit"]
        summary = audit["summary"]
        agent_rows = [
            (
                f"| `{agent['agent_id']}` | {agent['role']} | "
                f"{', '.join(agent['responsibilities'])} | {agent['guardrail']} |"
            )
            for agent in audit["agent_registry"]
        ]
        file_rows = [
            (
                f"| `{row['agent_id']}` | {row['stream']} | {row['exists']} | "
                f"{row['message_count']} | {row['malformed_count']} | `{row['path']}` |"
            )
            for row in audit["message_files"]
        ]
        route_rows = [
            f"| `{row['sender']}` | `{row['recipient']}` | {row['type']} | {row['message_count']} |"
            for row in audit["message_routes"]
        ] or ["| none | none | none | 0 |"]
        handoff_rows = [
            (
                f"| {row['handoff_type']} | `{row['sender']}` | `{row['recipient']}` | "
                f"{row['observed']} | {row['message_count']} |"
            )
            for row in audit["handoff_ledger"]
        ]
        gate_rows = [
            f"| `{gate['gate_id']}` | {gate['owner_role']} | {gate['status']} | {gate['requirement']} |"
            for gate in audit["control_gates"]
        ]
        queue_rows = [
            f"| {row['owner']} | {row['priority']} | {row['action']} | {row['evidence']} |"
            for row in audit["operator_queue"]
        ]
        command_rows = [f"- `{command}`" for command in pack["local_commands"]]
        criteria_rows = [f"- {item}" for item in pack["handoff_acceptance_criteria"]]
        limitation_rows = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Agent Coordination Bus Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: {audit['readiness_status']}",
                f"- Coordination score: {audit['coordination_score']}",
                f"- Bus root: `{audit['bus_root']}`",
                f"- Messages: {summary['message_count']}",
                f"- Malformed messages: {summary['malformed_message_count']}",
                f"- External calls: {summary['external_call_count']}",
                "",
                "## Agent Registry",
                "| Agent | Role | Responsibilities | Guardrail |",
                "| --- | --- | --- | --- |",
                *agent_rows,
                "",
                "## Message Files",
                "| Agent | Stream | Exists | Messages | Malformed | Path |",
                "| --- | --- | --- | ---: | ---: | --- |",
                *file_rows,
                "",
                "## Message Routes",
                "| Sender | Recipient | Type | Count |",
                "| --- | --- | --- | ---: |",
                *route_rows,
                "",
                "## Handoff Ledger",
                "| Handoff | Sender | Recipient | Observed | Count |",
                "| --- | --- | --- | --- | ---: |",
                *handoff_rows,
                "",
                "## Review Gates",
                "| Gate | Owner | Status | Requirement |",
                "| --- | --- | --- | --- |",
                *gate_rows,
                "",
                "## Operator Queue",
                "| Owner | Priority | Action | Evidence |",
                "| --- | --- | --- | --- |",
                *queue_rows,
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
