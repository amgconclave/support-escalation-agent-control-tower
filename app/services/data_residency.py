import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.storage import JsonStateStore
from app.models import AuditEvent, Ticket
from app.services.audit import AuditService
from app.services.tickets import TicketService


PII_PATTERNS = {
    "email_address": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "invoice_id": re.compile(r"\bINV-[0-9]{3,}\b", re.IGNORECASE),
    "tenant_identifier": re.compile(r"\b(?:tenant|workspace|account)\s+[a-z0-9_-]{3,}\b", re.IGNORECASE),
    "request_identifier": re.compile(r"\b(?:request|trace|ticket)[-_ ]?id(?:s)?\b", re.IGNORECASE),
    "api_or_access_key": re.compile(r"\b(?:api key|access token|secret|credential|bearer token)\b", re.IGNORECASE),
    "deleted_record_reference": re.compile(r"\bdeleted records?\b", re.IGNORECASE),
}

SENSITIVE_KEYWORDS = {
    "privacy",
    "data export",
    "deleted records",
    "compliance",
    "security",
    "api key",
    "access token",
    "saml",
    "sso",
    "patient",
    "bank",
}

DATA_RESIDENCY_ENDPOINTS = [
    "GET /compliance/data-residency-audit",
    "POST /compliance/data-residency-pack",
    "GET /tickets",
    "GET /integrations/outbox",
    "GET /evidence/retention-audit",
]

DATA_RESIDENCY_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "compliance/data-residency-audit|compliance/data-residency-pack|'
        r'Data Residency|data_residency_packs" app dashboard docs README.md tests scripts sample_data'
    ),
]


class DataResidencyService:
    """Audits local support data handling for PII and residency review risk."""

    def __init__(
        self,
        store: JsonStateStore,
        tickets: TicketService,
        audit: AuditService,
        customers_path: Path,
        rules_path: Path,
        packs_dir: Path,
    ):
        self.store = store
        self.tickets = tickets
        self.audit = audit
        self.customers_path = customers_path
        self.rules_path = rules_path
        self.packs_dir = packs_dir

    async def audit_residency(self) -> dict[str, Any]:
        tickets = await self.tickets.list()
        state = await self.store.load()
        customers = self._customers_by_name()
        rules = self._rules()
        exposure_rows = self._exposure_rows(tickets, state, customers, rules)
        flow_rows = self._flow_rows(state)
        summary = self._summary(exposure_rows, flow_rows)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "title": "Data Residency and PII Exposure Audit",
            "mode": "local-deterministic-data-residency-audit",
            "local_mock_only": True,
            "readiness_status": summary["readiness_status"],
            "residency_score": summary["residency_score"],
            "summary": summary,
            "policy_rules": rules,
            "account_exposure": exposure_rows,
            "data_flow_map": flow_rows,
            "control_checks": self._control_checks(exposure_rows, flow_rows),
            "owner_actions": self._owner_actions(exposure_rows, summary),
            "endpoint_list": DATA_RESIDENCY_ENDPOINTS,
            "evidence_sources": {
                "ticket_count": len(tickets),
                "run_count": len(state.get("runs", {})),
                "approval_count": len(state.get("approvals", {})),
                "outbox_event_count": len(state.get("outbox", {})),
                "customer_fixture": str(self.customers_path),
                "rules_fixture": str(self.rules_path),
                "artifact_directory": "data/data_residency_packs",
            },
            "local_commands": DATA_RESIDENCY_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_pack(self) -> dict[str, Any]:
        audit = await self.audit_residency()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"data_residency_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.packs_dir / f"{pack_id}.json"
        markdown_path = self.packs_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Data Residency and PII Exposure Pack",
            "audit": audit,
            "executive_summary": self._executive_summary(audit),
            "review_queue": self._review_queue(audit["account_exposure"]),
            "control_owner_actions": audit["owner_actions"],
            "acceptance_criteria": self._acceptance_criteria(),
            "local_commands": DATA_RESIDENCY_COMMANDS,
            "limitations": audit["limitations"],
            "artifact_paths": {
                "data_residency_markdown": str(markdown_path),
                "data_residency_json": str(json_path),
            },
        }
        markdown = self._markdown(pack)
        self.packs_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="data-residency",
                action="compliance.data_residency_pack_exported",
                resource_type="data_residency_pack",
                resource_id=pack_id,
                metadata={
                    "readiness_status": audit["readiness_status"],
                    "residency_score": audit["residency_score"],
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                },
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "readiness_status": audit["readiness_status"],
            "residency_score": audit["residency_score"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "pack": pack,
            "markdown": markdown,
        }

    def _customers_by_name(self) -> dict[str, dict[str, Any]]:
        if not self.customers_path.exists():
            return {}
        rows = json.loads(self.customers_path.read_text(encoding="utf-8"))
        return {row["customer"].lower(): row for row in rows}

    def _rules(self) -> dict[str, Any]:
        if not self.rules_path.exists():
            return {
                "default_processing_region": "local-dev",
                "restricted_regions": ["EU"],
                "sensitive_segments": ["Healthcare", "Financial Services"],
                "review_required_categories": ["security_privacy", "authentication"],
                "external_action_policy": "human_approval_required",
            }
        return json.loads(self.rules_path.read_text(encoding="utf-8"))

    def _exposure_rows(
        self,
        tickets: list[Ticket],
        state: dict[str, Any],
        customers: dict[str, dict[str, Any]],
        rules: dict[str, Any],
    ) -> list[dict[str, Any]]:
        latest_runs = self._latest_runs_by_ticket(state)
        rows = []
        for ticket in tickets:
            customer = customers.get((ticket.customer or "").lower(), {})
            run = latest_runs.get(ticket.ticket_id, {})
            run_state = run.get("state", {})
            approval_count = len(
                [item for item in state.get("approvals", {}).values() if item.get("ticket_id") == ticket.ticket_id]
            )
            outbox_events = [
                item for item in state.get("outbox", {}).values() if item.get("ticket_id") == ticket.ticket_id
            ]
            text_sources = self._text_sources(ticket, run, outbox_events)
            signals = self._pii_signals(text_sources)
            category = run_state.get("classification", {}).get("category") or self._category_from_ticket(ticket)
            region = customer.get("region", "unknown")
            segment = customer.get("segment", "unknown")
            risk_reasons = self._risk_reasons(
                signals=signals,
                region=region,
                segment=segment,
                category=category,
                outbox_events=outbox_events,
                approval_count=approval_count,
                rules=rules,
            )
            severity = self._severity(risk_reasons)
            rows.append(
                {
                    "ticket_id": ticket.ticket_id,
                    "customer": ticket.customer or "unknown",
                    "region": region,
                    "segment": segment,
                    "tier": customer.get("tier", ticket.customer_tier),
                    "category": category,
                    "priority": ticket.priority,
                    "status": ticket.status,
                    "pii_signal_count": sum(item["count"] for item in signals),
                    "pii_signal_types": [item["signal_type"] for item in signals],
                    "external_outbox_count": len(outbox_events),
                    "approval_count": approval_count,
                    "human_approval_present": approval_count > 0,
                    "risk_reasons": risk_reasons,
                    "severity": severity,
                    "recommended_action": self._recommended_action(severity, risk_reasons),
                }
            )
        return sorted(rows, key=lambda item: (self._severity_rank(item["severity"]), -item["pii_signal_count"], item["customer"]))

    def _latest_runs_by_ticket(self, state: dict[str, Any]) -> dict[str, dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for run in state.get("runs", {}).values():
            grouped[run.get("ticket_id", "")].append(run)
        return {
            ticket_id: sorted(
                runs,
                key=lambda item: item.get("completed_at") or item.get("started_at") or "",
                reverse=True,
            )[0]
            for ticket_id, runs in grouped.items()
            if ticket_id
        }

    def _text_sources(
        self,
        ticket: Ticket,
        run: dict[str, Any],
        outbox_events: list[dict[str, Any]],
    ) -> dict[str, str]:
        run_state = run.get("state", {})
        payload_text = " ".join(json.dumps(item.get("payload", {}), default=str) for item in outbox_events)
        return {
            "ticket": " ".join([ticket.subject, ticket.body, ticket.customer_email, " ".join(ticket.tags)]),
            "customer_reply": run_state.get("customer_reply", ""),
            "engineering_escalation": run_state.get("engineering_escalation", ""),
            "outbox_payload": payload_text,
        }

    def _pii_signals(self, sources: dict[str, str]) -> list[dict[str, Any]]:
        rows = []
        for signal_type, pattern in PII_PATTERNS.items():
            source_counts = {
                source: len(pattern.findall(text or ""))
                for source, text in sources.items()
            }
            count = sum(source_counts.values())
            if count:
                rows.append(
                    {
                        "signal_type": signal_type,
                        "count": count,
                        "sources": [source for source, source_count in source_counts.items() if source_count],
                    }
                )
        lower_text = " ".join(sources.values()).lower()
        for keyword in sorted(SENSITIVE_KEYWORDS):
            if keyword in lower_text:
                rows.append({"signal_type": f"keyword:{keyword.replace(' ', '_')}", "count": 1, "sources": ["semantic_scan"]})
        return rows

    def _risk_reasons(
        self,
        signals: list[dict[str, Any]],
        region: str,
        segment: str,
        category: str,
        outbox_events: list[dict[str, Any]],
        approval_count: int,
        rules: dict[str, Any],
    ) -> list[str]:
        signal_types = {item["signal_type"] for item in signals}
        reasons = []
        if signals:
            reasons.append("pii_or_sensitive_support_data_detected")
        if region in set(rules.get("restricted_regions", [])):
            reasons.append("restricted_region_review_required")
        if segment in set(rules.get("sensitive_segments", [])):
            reasons.append("regulated_segment_review_required")
        if category in set(rules.get("review_required_categories", [])):
            reasons.append("sensitive_workflow_category")
        if outbox_events and signals:
            reasons.append("sensitive_data_reached_integration_outbox")
        if outbox_events and approval_count == 0:
            reasons.append("external_action_without_recorded_approval")
        if "api_or_access_key" in signal_types or "keyword:api_key" in signal_types or "keyword:access_token" in signal_types:
            reasons.append("credential_rotation_or_secret_context")
        if "deleted_record_reference" in signal_types or "keyword:deleted_records" in signal_types:
            reasons.append("privacy_deletion_context")
        return reasons or ["no_material_residency_or_pii_risk_detected"]

    def _severity(self, reasons: list[str]) -> str:
        critical = {"external_action_without_recorded_approval", "credential_rotation_or_secret_context"}
        high = {
            "restricted_region_review_required",
            "regulated_segment_review_required",
            "sensitive_data_reached_integration_outbox",
            "privacy_deletion_context",
        }
        if any(reason in critical for reason in reasons):
            return "critical"
        if any(reason in high for reason in reasons):
            return "high"
        if "pii_or_sensitive_support_data_detected" in reasons or "sensitive_workflow_category" in reasons:
            return "medium"
        return "low"

    def _severity_rank(self, severity: str) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)

    def _category_from_ticket(self, ticket: Ticket) -> str:
        text = " ".join([ticket.subject, ticket.body, " ".join(ticket.tags)]).lower()
        if any(token in text for token in ["privacy", "data export", "deleted", "security"]):
            return "security_privacy"
        if any(token in text for token in ["sso", "saml", "auth", "login"]):
            return "authentication"
        if any(token in text for token in ["api", "webhook", "request id"]):
            return "api_integrations"
        if any(token in text for token in ["invoice", "billing"]):
            return "billing"
        return "general_support"

    def _flow_rows(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            self._flow_row("ticket_intake", len(state.get("tickets", {})), "Ticket subject, body, customer email, tags"),
            self._flow_row("agent_run_state", len(state.get("runs", {})), "Classification, SLA risk, drafts, citations"),
            self._flow_row("approval_queue", len(state.get("approvals", {})), "Customer reply and engineering escalation awaiting review"),
            self._flow_row("integration_outbox", len(state.get("outbox", {})), "Approved fake Zendesk/Jira/Slack/customer dispatch payloads"),
            self._flow_row("audit_events", len(state.get("audit_events", {})), "Actor/action/resource metadata for local compliance review"),
        ]

    def _flow_row(self, data_store: str, record_count: int, handled_data: str) -> dict[str, Any]:
        return {
            "data_store": data_store,
            "record_count": record_count,
            "handled_data": handled_data,
            "processing_location": "local developer machine",
            "external_service_call": False,
            "retention_boundary": "ignored local SQLite/data artifacts",
        }

    def _summary(self, rows: list[dict[str, Any]], flows: list[dict[str, Any]]) -> dict[str, Any]:
        severity_counts = Counter(row["severity"] for row in rows)
        reasons = Counter(reason for row in rows for reason in row["risk_reasons"])
        score = 100
        score -= severity_counts["critical"] * 22
        score -= severity_counts["high"] * 14
        score -= severity_counts["medium"] * 7
        score -= min(12, reasons["sensitive_data_reached_integration_outbox"] * 4)
        score = max(0, min(100, score))
        status = "ready"
        if severity_counts["critical"]:
            status = "blocked_until_compliance_review"
        elif severity_counts["high"]:
            status = "review_required"
        elif severity_counts["medium"]:
            status = "ready_with_monitoring"
        return {
            "readiness_status": status,
            "residency_score": score,
            "ticket_count": len(rows),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "restricted_region_ticket_count": reasons["restricted_region_review_required"],
            "regulated_segment_ticket_count": reasons["regulated_segment_review_required"],
            "pii_signal_ticket_count": len([row for row in rows if row["pii_signal_count"] > 0]),
            "outbox_exposure_ticket_count": reasons["sensitive_data_reached_integration_outbox"],
            "local_data_store_count": len(flows),
            "external_service_call_count": len([row for row in flows if row["external_service_call"]]),
        }

    def _control_checks(self, rows: list[dict[str, Any]], flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "control": "local_only_processing",
                "status": "pass" if not any(row["external_service_call"] for row in flows) else "fail",
                "evidence": "All audited support data stores are local/mock and no SaaS adapter call is made by this audit.",
                "owner": "Platform Engineering",
            },
            {
                "control": "human_approval_before_external_action",
                "status": "pass"
                if not any(row["external_outbox_count"] and not row["human_approval_present"] for row in rows)
                else "fail",
                "evidence": "Outbox exposure rows are checked for a recorded approval.",
                "owner": "Support Operations",
            },
            {
                "control": "restricted_region_visibility",
                "status": "pass",
                "evidence": "EU and regulated-segment tickets are surfaced in the review queue before production integration work.",
                "owner": "Compliance",
            },
            {
                "control": "pii_redaction_review",
                "status": "warn" if any(row["pii_signal_count"] for row in rows) else "pass",
                "evidence": "The audit detects emails, invoice IDs, tenant IDs, request IDs, credential context, and privacy deletion context.",
                "owner": "Security",
            },
        ]

    def _owner_actions(self, rows: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
        risky = [row for row in rows if row["severity"] in {"critical", "high"}]
        if not risky:
            return [
                {
                    "owner": "Support Operations",
                    "priority": "low",
                    "action": "Keep the data residency audit in the local demo and rerun it when fixtures change.",
                    "acceptance_criteria": "Audit remains ready or ready_with_monitoring with no critical rows.",
                }
            ]
        return [
            {
                "owner": "Compliance",
                "priority": "high" if summary["critical_count"] == 0 else "critical",
                "action": "Review restricted-region and regulated-segment support tickets before enabling production adapters.",
                "acceptance_criteria": "Every critical/high row has documented approval, redaction guidance, and an owner.",
            },
            {
                "owner": "Security",
                "priority": "high",
                "action": "Add redaction checks for credential, invoice, tenant, request ID, and deletion-context signals.",
                "acceptance_criteria": "Credential and privacy-deletion findings are blocked or manually approved before outbox dispatch.",
            },
            {
                "owner": "Support Operations",
                "priority": "medium",
                "action": "Use the dashboard Data Residency tab during account review and incident handoff.",
                "acceptance_criteria": "Review queue is exported as Markdown/JSON under data/data_residency_packs.",
            },
        ]

    def _recommended_action(self, severity: str, reasons: list[str]) -> str:
        if severity == "critical":
            return "Block production adapter dispatch until compliance/security review closes the critical finding."
        if severity == "high":
            return "Route to compliance review and confirm approval/redaction before external customer or engineering actions."
        if severity == "medium":
            return "Confirm standard approval captured the sensitive support context before dispatch."
        return "No immediate compliance action; keep local-only audit evidence."

    def _executive_summary(self, audit: dict[str, Any]) -> list[str]:
        summary = audit["summary"]
        return [
            f"Data residency readiness is {audit['readiness_status']} with score {audit['residency_score']}.",
            (
                f"{summary['critical_count']} critical, {summary['high_count']} high, "
                f"and {summary['medium_count']} medium ticket rows need review."
            ),
            (
                f"{summary['restricted_region_ticket_count']} restricted-region and "
                f"{summary['regulated_segment_ticket_count']} regulated-segment rows were found."
            ),
            "The audit is local/mock only and does not call a DLP, CRM, ticketing, warehouse, Azure, or OpenAI service.",
        ]

    def _review_queue(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "ticket_id": row["ticket_id"],
                "customer": row["customer"],
                "region": row["region"],
                "severity": row["severity"],
                "risk_reasons": row["risk_reasons"],
                "recommended_action": row["recommended_action"],
            }
            for row in rows
            if row["severity"] in {"critical", "high", "medium"}
        ]

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Critical rows are zero before production adapters are enabled.",
            "EU and regulated-segment support tickets have explicit compliance owner review.",
            "External outbox payloads with sensitive signals have a recorded human approval.",
            "Generated data_residency_packs Markdown/JSON artifacts are ignored local evidence.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "This is a deterministic local audit, not a legal compliance opinion.",
            "Pattern matching is intentionally conservative and does not replace enterprise DLP tooling.",
            "Region, segment, and ARR metadata come from bundled fake fixtures, not CRM or contract systems.",
            "Generated files under data/data_residency_packs are ignored local artifacts and should be regenerated.",
            "The audit does not call Azure, OpenAI, Zendesk, Jira, Slack, GitHub, DLP, SIEM, warehouse, or external storage APIs.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        audit = pack["audit"]
        summary = audit["summary"]
        executive = [f"- {item}" for item in pack["executive_summary"]]
        queue_rows = [
            (
                f"| {row['ticket_id']} | {row['customer']} | {row['region']} | "
                f"{row['severity']} | {', '.join(row['risk_reasons'])} |"
            )
            for row in pack["review_queue"]
        ] or ["| None | none | none | low | No open review rows |"]
        action_rows = [
            f"- **{item['owner']}** ({item['priority']}): {item['action']}"
            for item in pack["control_owner_actions"]
        ]
        command_rows = [f"- `{command}`" for command in pack["local_commands"]]
        limitation_rows = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# {pack['title']}",
                "",
                f"- Pack ID: `{pack['pack_id']}`",
                f"- Generated at: `{pack['generated_at']}`",
                f"- Readiness: `{audit['readiness_status']}`",
                f"- Residency score: `{audit['residency_score']}`",
                "",
                "## Executive Summary",
                *executive,
                "",
                "## Summary Metrics",
                f"- Tickets audited: {summary['ticket_count']}",
                f"- Critical/high/medium: {summary['critical_count']} / {summary['high_count']} / {summary['medium_count']}",
                f"- PII signal tickets: {summary['pii_signal_ticket_count']}",
                f"- Outbox exposure tickets: {summary['outbox_exposure_ticket_count']}",
                "",
                "## Review Queue",
                "| Ticket | Customer | Region | Severity | Reasons |",
                "| --- | --- | --- | --- | --- |",
                *queue_rows,
                "",
                "## Control Owner Actions",
                *action_rows,
                "",
                "## Acceptance Criteria",
                *[f"- {item}" for item in pack["acceptance_criteria"]],
                "",
                "## Local Verification Commands",
                *command_rows,
                "",
                "## Limitations",
                *limitation_rows,
                "",
            ]
        )
