import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.storage import JsonStateStore
from app.models import AuditEvent
from app.services.audit import AuditService


EVIDENCE_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "evidence/retention-audit|evidence/retention-pack|Evidence Retention|'
        r'evidence_packs|chain-of-custody" app dashboard docs README.md tests scripts'
    ),
]

EVIDENCE_ARTIFACT_DIRECTORIES = [
    "briefs",
    "checklists",
    "reports",
    "account_briefs",
    "renewal_reviews",
    "optimization_reports",
    "demo_packs",
    "operator_packs",
    "replay_reports",
    "policy_packs",
    "policy_change_packs",
    "incident_narratives",
    "rca_packs",
    "finance_impact_packs",
    "leadership_reviews",
    "kb_refresh_plans",
    "runbook_gap_packs",
    "launch_checklists",
    "portfolio_packs",
    "release_packs",
    "reviewer_packs",
    "audit_packs",
    "artifact_indexes",
    "ui_verification",
    "final_handoff",
    "customer_comms_packs",
    "git_packs",
    "api_contracts",
    "runtime_packs",
    "scenario_packs",
    "data_residency_packs",
    "access_review_packs",
]


class EvidenceRetentionService:
    """Audits local evidence completeness and exports chain-of-custody proof."""

    def __init__(self, store: JsonStateStore, audit: AuditService, evidence_dir: Path):
        self.store = store
        self.audit = audit
        self.evidence_dir = evidence_dir
        self.data_root = evidence_dir.parent
        self.repo_root = Path(__file__).resolve().parents[2]

    async def retention_audit(self) -> dict[str, Any]:
        state = await self.store.load()
        runs = sorted(
            state["runs"].values(),
            key=lambda item: item.get("started_at") or item.get("completed_at") or "",
            reverse=True,
        )
        run_rows = [self._run_evidence_row(run, state) for run in runs[:15]]
        artifact_summary = self._artifact_summary()
        hash_manifest = self._hash_manifest()
        controls = self._retention_controls()
        findings = self._findings(state, run_rows, artifact_summary, hash_manifest)
        score = self._score(findings, run_rows, artifact_summary, hash_manifest)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Evidence Retention Audit",
            "mode": "local-deterministic-evidence-retention",
            "local_mock_only": True,
            "status": self._status(score, findings),
            "readiness_score": score,
            "state_counts": self._state_counts(state),
            "retention_controls": controls,
            "run_evidence_map": run_rows,
            "artifact_summary": artifact_summary,
            "hash_manifest": hash_manifest,
            "findings": findings,
            "recommended_actions": self._recommended_actions(findings, artifact_summary),
            "local_commands": EVIDENCE_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_retention_pack(self) -> dict[str, Any]:
        audit = await self.retention_audit()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"evidence_retention_{generated_at.strftime('%Y%m%d_%H%M%S')}"
        json_path = self.evidence_dir / f"{pack_id}.json"
        markdown_path = self.evidence_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Evidence Retention and Chain-of-Custody Pack",
            "retention_audit": audit,
            "executive_summary": self._executive_summary(audit),
            "custody_review_table": self._custody_review_table(audit),
            "control_owner_actions": self._control_owner_actions(audit),
            "artifact_paths": {
                "evidence_retention_markdown": str(markdown_path),
                "evidence_retention_json": str(json_path),
            },
        }
        markdown = self._markdown(pack)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="evidence-retention",
                action="evidence.retention_pack_exported",
                resource_type="evidence_pack",
                resource_id=pack_id,
                metadata={
                    "status": audit["status"],
                    "readiness_score": audit["readiness_score"],
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                },
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": audit["status"],
            "readiness_score": audit["readiness_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    def _state_counts(self, state: dict[str, Any]) -> dict[str, int]:
        return {
            "ticket_count": len(state["tickets"]),
            "run_count": len(state["runs"]),
            "trace_event_count": sum(len(events) for events in state["traces"].values()),
            "approval_count": len(state["approvals"]),
            "outbox_event_count": len(state["outbox"]),
            "audit_event_count": len(state["audit_events"]),
            "metric_node_count": len(state.get("metrics", {}).get("node_metrics", {})),
        }

    def _run_evidence_row(self, run: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        run_id = run.get("run_id") or run.get("id", "")
        ticket_id = run.get("ticket_id", "")
        trace_events = state["traces"].get(run_id, [])
        approvals = [item for item in state["approvals"].values() if item.get("run_id") == run_id]
        outbox = [item for item in state["outbox"].values() if item.get("run_id") == run_id]
        audit_events = [
            item
            for item in state["audit_events"].values()
            if item.get("resource_id") in {run_id, ticket_id} or item.get("trace_id") == run.get("trace_id")
        ]
        required = {
            "ticket": bool(ticket_id and ticket_id in state["tickets"]),
            "trace": bool(trace_events),
            "classification": bool(run.get("state", {}).get("classification")),
            "sla_risk": bool(run.get("state", {}).get("sla_risk")),
            "qa": bool(run.get("state", {}).get("qa")),
            "approval": bool(approvals) or run.get("status") in {"human_review", "rejected"},
            "audit": bool(audit_events),
        }
        if run.get("status") == "completed":
            required["outbox"] = bool(outbox)
        missing = [name for name, present in required.items() if not present]
        return {
            "run_id": run_id,
            "ticket_id": ticket_id,
            "trace_id": run.get("trace_id", ""),
            "status": run.get("status", ""),
            "final_action": run.get("final_action", ""),
            "trace_event_count": len(trace_events),
            "approval_count": len(approvals),
            "outbox_event_count": len(outbox),
            "audit_event_count": len(audit_events),
            "required_evidence": required,
            "missing_evidence": missing,
            "completeness_status": "complete" if not missing else "gap",
        }

    def _artifact_summary(self) -> dict[str, Any]:
        rows = [self._artifact_directory_row(name) for name in EVIDENCE_ARTIFACT_DIRECTORIES]
        generated = [row for row in rows if row["file_count"] > 0]
        return {
            "artifact_directory_count": len(rows),
            "generated_directory_count": len(generated),
            "missing_directory_count": len(rows) - len(generated),
            "total_file_count": sum(row["file_count"] for row in rows),
            "directories": rows,
        }

    def _artifact_directory_row(self, name: str) -> dict[str, Any]:
        path = self.data_root / name
        files = self._artifact_files(path)
        latest = files[0] if files else None
        return {
            "directory": f"data/{name}",
            "resolved_directory": str(path),
            "file_count": len(files),
            "latest_file": str(latest) if latest else "not generated yet",
            "latest_file_age_hours": self._age_hours(latest) if latest else None,
            "custody_status": "present" if files else "not_generated",
        }

    def _artifact_files(self, directory: Path) -> list[Path]:
        if not directory.exists():
            return []
        files = [
            path
            for path in directory.iterdir()
            if path.is_file() and path.suffix.lower() in {".md", ".json"}
        ]
        return sorted(files, key=lambda path: (path.stat().st_mtime, path.name), reverse=True)

    def _hash_manifest(self) -> dict[str, Any]:
        candidates: list[Path] = []
        for directory in EVIDENCE_ARTIFACT_DIRECTORIES:
            candidates.extend(self._artifact_files(self.data_root / directory)[:2])
        candidates = sorted(candidates, key=lambda path: (path.stat().st_mtime, path.name), reverse=True)[:40]
        files = [self._hash_row(path) for path in candidates]
        return {
            "algorithm": "sha256",
            "file_count": len(files),
            "manifest_scope": "latest Markdown/JSON files across local generated evidence directories",
            "files": files,
        }

    def _hash_row(self, path: Path) -> dict[str, Any]:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "last_write_time": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            "sha256": digest,
        }

    def _age_hours(self, path: Path) -> float:
        seconds = datetime.now(timezone.utc).timestamp() - path.stat().st_mtime
        return round(seconds / 3600, 2)

    def _retention_controls(self) -> list[dict[str, str]]:
        return [
            {
                "control": "Local durable state",
                "implementation": "Tickets, runs, traces, approvals, outbox, audit events, and metrics are persisted in the local SQLite-backed state document.",
                "owner": "Support Operations",
            },
            {
                "control": "Human approval custody",
                "implementation": "Risky customer-visible and engineering-facing actions require approval records before fake dispatch.",
                "owner": "Support Lead",
            },
            {
                "control": "Generated artifact retention",
                "implementation": "Markdown/JSON packs are written under ignored data/ directories and can be regenerated locally.",
                "owner": "Incident Commander",
            },
            {
                "control": "Hash manifest",
                "implementation": "The retention pack computes SHA-256 hashes for latest local evidence artifacts to detect accidental edits.",
                "owner": "Release Reviewer",
            },
            {
                "control": "External system boundary",
                "implementation": "The audit does not call CRM, billing, GitHub, Azure, OpenAI, Zendesk, Jira, Slack, or other SaaS APIs.",
                "owner": "Platform Engineering",
            },
        ]

    def _findings(
        self,
        state: dict[str, Any],
        run_rows: list[dict[str, Any]],
        artifact_summary: dict[str, Any],
        hash_manifest: dict[str, Any],
    ) -> list[dict[str, str]]:
        findings = []
        counts = self._state_counts(state)
        if counts["run_count"] == 0:
            findings.append(
                {
                    "severity": "high",
                    "finding": "No workflow runs are available for evidence retention review.",
                    "recommendation": "Run scripts/demo_run.py or analyze a sample ticket before final review.",
                }
            )
        if any(row["completeness_status"] == "gap" for row in run_rows):
            findings.append(
                {
                    "severity": "medium",
                    "finding": "One or more recent runs are missing expected trace, approval, audit, or outbox evidence.",
                    "recommendation": "Inspect run_evidence_map and regenerate affected incident artifacts.",
                }
            )
        if artifact_summary["generated_directory_count"] < 8:
            findings.append(
                {
                    "severity": "medium",
                    "finding": "Generated evidence coverage is thin for an executive/reviewer handoff.",
                    "recommendation": "Run scripts/demo_run.py to refresh the full local artifact set.",
                }
            )
        if hash_manifest["file_count"] == 0:
            findings.append(
                {
                    "severity": "medium",
                    "finding": "No local artifact files were available for chain-of-custody hashing.",
                    "recommendation": "Export one or more Markdown/JSON packs before signing off.",
                }
            )
        if counts["audit_event_count"] == 0:
            findings.append(
                {
                    "severity": "medium",
                    "finding": "No audit events have been recorded in local state.",
                    "recommendation": "Run an approval or export workflow that records an audit event.",
                }
            )
        if not findings:
            findings.append(
                {
                    "severity": "info",
                    "finding": "Recent local evidence has trace, approval, audit, and artifact custody coverage.",
                    "recommendation": "Export a fresh retention pack before sharing the repository.",
                }
            )
        return findings

    def _score(
        self,
        findings: list[dict[str, str]],
        run_rows: list[dict[str, Any]],
        artifact_summary: dict[str, Any],
        hash_manifest: dict[str, Any],
    ) -> int:
        score = 100
        score -= 30 * sum(1 for item in findings if item["severity"] == "high")
        score -= 12 * sum(1 for item in findings if item["severity"] == "medium")
        score -= 6 * sum(1 for row in run_rows if row["completeness_status"] == "gap")
        if artifact_summary["artifact_directory_count"]:
            missing_ratio = artifact_summary["missing_directory_count"] / artifact_summary["artifact_directory_count"]
            score -= int(missing_ratio * 20)
        if hash_manifest["file_count"] < 4:
            score -= 8
        return max(0, min(100, score))

    def _status(self, score: int, findings: list[dict[str, str]]) -> str:
        if any(item["severity"] == "high" for item in findings):
            return "blocked"
        if score < 80 or any(item["severity"] == "medium" for item in findings):
            return "review_ready_with_evidence_gaps"
        return "ready"

    def _recommended_actions(
        self,
        findings: list[dict[str, str]],
        artifact_summary: dict[str, Any],
    ) -> list[dict[str, str]]:
        actions = [
            {
                "owner": "Support Lead",
                "action": item["recommendation"],
                "source_finding": item["finding"],
            }
            for item in findings
            if item["severity"] != "info"
        ]
        if not actions:
            actions.append(
                {
                    "owner": "Release Reviewer",
                    "action": "Attach the retention pack path to the final portfolio handoff notes.",
                    "source_finding": "Evidence retention is ready.",
                }
            )
        actions.append(
            {
                "owner": "Incident Commander",
                "action": (
                    "Confirm generated evidence directories remain ignored under data/ "
                    f"({artifact_summary['generated_directory_count']} generated directories found)."
                ),
                "source_finding": "Generated artifacts are local proof, not source files.",
            }
        )
        return actions

    def _executive_summary(self, audit: dict[str, Any]) -> str:
        counts = audit["state_counts"]
        artifacts = audit["artifact_summary"]
        return (
            f"Evidence retention status is {audit['status']} with score {audit['readiness_score']}. "
            f"The local state contains {counts['run_count']} runs, {counts['trace_event_count']} trace events, "
            f"{counts['approval_count']} approvals, {counts['outbox_event_count']} outbox records, and "
            f"{counts['audit_event_count']} audit events. The custody manifest covers "
            f"{audit['hash_manifest']['file_count']} recent artifact files across "
            f"{artifacts['generated_directory_count']} generated directories."
        )

    def _custody_review_table(self, audit: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {
                "surface": "Workflow state",
                "status": "present" if audit["state_counts"]["run_count"] else "missing",
                "evidence": f"{audit['state_counts']['run_count']} runs and {audit['state_counts']['trace_event_count']} trace events",
                "owner": "Support Operations",
            },
            {
                "surface": "Human approval",
                "status": "present" if audit["state_counts"]["approval_count"] else "missing",
                "evidence": f"{audit['state_counts']['approval_count']} approval records",
                "owner": "Support Lead",
            },
            {
                "surface": "Fake dispatch outbox",
                "status": "present" if audit["state_counts"]["outbox_event_count"] else "missing",
                "evidence": f"{audit['state_counts']['outbox_event_count']} outbox records",
                "owner": "Incident Commander",
            },
            {
                "surface": "Generated artifacts",
                "status": "present" if audit["artifact_summary"]["generated_directory_count"] else "missing",
                "evidence": f"{audit['artifact_summary']['total_file_count']} Markdown/JSON files",
                "owner": "Release Reviewer",
            },
            {
                "surface": "Hash manifest",
                "status": "present" if audit["hash_manifest"]["file_count"] else "missing",
                "evidence": f"{audit['hash_manifest']['file_count']} SHA-256 hashes",
                "owner": "Platform Engineering",
            },
        ]

    def _control_owner_actions(self, audit: dict[str, Any]) -> list[dict[str, str]]:
        rows = []
        for control in audit["retention_controls"]:
            rows.append(
                {
                    "owner": control["owner"],
                    "control": control["control"],
                    "next_action": "Review current pack and confirm no external system data is required.",
                }
            )
        return rows

    def _limitations(self) -> list[str]:
        return [
            "Retention checks inspect local state and generated data/ artifacts only.",
            "The hash manifest is a local integrity aid, not a legal hold, SIEM export, or notarized signature.",
            "No CRM, billing, contract, GitHub, Azure, OpenAI, Zendesk, Jira, Slack, or external archive is queried.",
            "Generated data/ artifacts are ignored by design and should be regenerated rather than committed.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        audit = pack["retention_audit"]
        counts = audit["state_counts"]
        custody_rows = [
            f"| {row['surface']} | {row['status']} | {row['evidence']} | {row['owner']} |"
            for row in pack["custody_review_table"]
        ]
        run_rows = [
            (
                f"| `{row['run_id']}` | {row['status']} | {row['trace_event_count']} | "
                f"{row['approval_count']} | {row['outbox_event_count']} | {', '.join(row['missing_evidence']) or 'none'} |"
            )
            for row in audit["run_evidence_map"][:10]
        ] or ["| none | n/a | 0 | 0 | 0 | no runs available |"]
        artifact_rows = [
            f"| `{row['directory']}` | {row['file_count']} | `{row['latest_file']}` | {row['custody_status']} |"
            for row in audit["artifact_summary"]["directories"]
            if row["file_count"] > 0
        ][:20] or ["| none | 0 | `not generated yet` | missing |"]
        hash_rows = [
            f"| `{row['path']}` | {row['size_bytes']} | `{row['sha256'][:16]}...` |"
            for row in audit["hash_manifest"]["files"][:12]
        ] or ["| none | 0 | no hash available |"]
        finding_rows = [
            f"- **{item['severity']}**: {item['finding']} Recommendation: {item['recommendation']}"
            for item in audit["findings"]
        ]
        action_rows = [
            f"- **{item['owner']}**: {item['action']}"
            for item in audit["recommended_actions"]
        ]
        command_rows = [f"- `{command}`" for command in audit["local_commands"]]
        limitation_rows = [f"- {item}" for item in audit["limitations"]]
        return "\n".join(
            [
                f"# Evidence Retention and Chain-of-Custody Pack: {pack['pack_id']}",
                "",
                "## Executive Summary",
                pack["executive_summary"],
                "",
                "## Readiness",
                f"- Status: **{audit['status']}**",
                f"- Score: {audit['readiness_score']}",
                f"- Runs: {counts['run_count']}",
                f"- Trace events: {counts['trace_event_count']}",
                f"- Approvals: {counts['approval_count']}",
                f"- Outbox events: {counts['outbox_event_count']}",
                f"- Audit events: {counts['audit_event_count']}",
                "",
                "## Custody Review Table",
                "| Surface | Status | Evidence | Owner |",
                "| --- | --- | --- | --- |",
                *custody_rows,
                "",
                "## Recent Run Evidence",
                "| Run | Status | Trace Events | Approvals | Outbox | Missing Evidence |",
                "| --- | --- | ---: | ---: | ---: | --- |",
                *run_rows,
                "",
                "## Generated Artifact Custody",
                "| Directory | Files | Latest File | Status |",
                "| --- | ---: | --- | --- |",
                *artifact_rows,
                "",
                "## Hash Manifest Sample",
                "| Path | Bytes | SHA-256 Prefix |",
                "| --- | ---: | --- |",
                *hash_rows,
                "",
                "## Findings",
                *finding_rows,
                "",
                "## Recommended Actions",
                *action_rows,
                "",
                "## Local Verification Commands",
                *command_rows,
                "",
                "## Limitations",
                *limitation_rows,
                "",
            ]
        )
