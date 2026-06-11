import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models import AuditEvent, Ticket, TicketCreate
from app.services.audit import AuditService
from app.services.playbooks import PlaybookService
from app.services.tickets import TicketService


RUNBOOK_CATEGORY_TAGS = {
    "authentication": {"auth", "sso", "login", "oauth", "saml", "mfa", "outage"},
    "billing": {"billing", "invoice", "refund", "finance", "credit", "renewal"},
    "api_integrations": {
        "api",
        "webhook",
        "latency",
        "5xx",
        "500",
        "integration",
        "retry",
        "rotation",
        "regression",
    },
    "security_privacy": {
        "privacy",
        "data",
        "compliance",
        "security",
        "deletion",
        "export",
        "breach",
    },
    "incident": {"incident", "outage", "sla", "production", "blocked", "breach"},
    "how_to": {"how_to", "how-to", "rotation", "api", "key", "question"},
    "general_support": {"reply", "support", "qa", "customer", "help"},
}

HIGH_IMPACT_TYPES = {"authentication", "api_integrations", "security_privacy", "incident"}
RUNBOOK_CONFIDENCE_THRESHOLD = 0.45

RUNBOOK_COVERAGE_ENDPOINTS = [
    "GET /runbooks/coverage-audit",
    "POST /runbooks/gap-pack",
    "POST /playbooks/recommend",
    "POST /runs/{run_id}/remediation-checklist",
    "GET /knowledge/quality-audit",
]

RUNBOOK_COVERAGE_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "runbooks/coverage-audit|runbooks/gap-pack|Runbook Coverage|'
        r'runbook_gap_packs" app dashboard docs README.md tests scripts'
    ),
]

RUNBOOK_REPO_RADAR_PATTERNS = [
    "role playbooks",
    "task delegation",
    "process modes",
    "artifact handoffs",
    "review gates",
    "run transparency",
]

RUNBOOK_ROLE_PLAYBOOKS = [
    {
        "role_id": "runbook_program_owner",
        "role": "Runbook Program Owner",
        "mission": "Own runbook inventory health, gap prioritization, and acceptance criteria.",
        "coverage_scope": ["coverage_score", "missing_dedicated_runbook", "review_cadence"],
        "guardrail": "Cannot mark a gap closed until a ticket maps to KB evidence and a runbook.",
    },
    {
        "role_id": "kb_curator",
        "role": "Knowledge Curator",
        "mission": "Retag or add KB articles so ticket language resolves to source guidance.",
        "coverage_scope": ["kb_article_mapping", "citation_readiness", "fixture_quality"],
        "guardrail": "Must preserve source-backed guidance; no external KB writes in local mode.",
    },
    {
        "role_id": "escalation_owner",
        "role": "Escalation Owner",
        "mission": "Confirm operating procedure, severity rules, and handoff expectations.",
        "coverage_scope": ["owner_assignment", "severity_policy", "engineering_handoff"],
        "guardrail": "Engineering-facing actions remain drafts until human approval.",
    },
    {
        "role_id": "ops_reviewer",
        "role": "Operations Reviewer",
        "mission": "Review gates, endpoint proof, local commands, and generated artifacts.",
        "coverage_scope": ["review_gates", "artifact_handoffs", "run_transparency"],
        "guardrail": "Must keep audit evidence local and reproducible without paid services.",
    },
]

RUNBOOK_PROCESS_MODES = {
    "continuous_monitoring": {
        "description": "All high-impact coverage is acceptable; monitor fixtures and new ticket types.",
        "review_cadence": "weekly",
        "max_parallel_owner_tasks": 2,
        "requires_executive_review": False,
    },
    "targeted_backlog": {
        "description": "Partial coverage exists; assign backlog tasks to close medium and low gaps.",
        "review_cadence": "twice-weekly",
        "max_parallel_owner_tasks": 4,
        "requires_executive_review": False,
    },
    "urgent_gap_remediation": {
        "description": "High-impact runbook gaps exist; route owners through explicit review gates.",
        "review_cadence": "daily until closed",
        "max_parallel_owner_tasks": 6,
        "requires_executive_review": True,
    },
}


class RunbookCoverageService:
    """Maps support tickets to KB/runbook coverage and exports owner-ready gap packs."""

    def __init__(
        self,
        tickets: TicketService,
        playbooks: PlaybookService,
        audit: AuditService,
        kb_fixture_path: Path,
        scenarios_path: Path,
        gap_packs_dir: Path,
    ):
        self.tickets = tickets
        self.playbooks = playbooks
        self.audit = audit
        self.kb_fixture_path = kb_fixture_path
        self.scenarios_path = scenarios_path
        self.gap_packs_dir = gap_packs_dir

    async def coverage_audit(self) -> dict[str, Any]:
        active_tickets = await self.tickets.list()
        scenario_tickets = self._scenario_tickets()
        articles = self._load_json(self.kb_fixture_path)
        playbooks = self.playbooks.list_playbooks()
        ticket_mappings = [
            self._ticket_mapping(item, articles, playbooks)
            for item in [*active_tickets, *scenario_tickets]
        ]
        gaps = self._runbook_gaps(ticket_mappings)
        owner_assignments = self._owner_assignments(gaps, ticket_mappings)
        summary = self._coverage_summary(ticket_mappings, gaps)
        process_mode = self._select_process_mode(summary, gaps)
        review_gates = self._review_gates(summary, gaps, ticket_mappings, owner_assignments)
        artifact_handoffs = self._artifact_handoffs(summary, gaps)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "local-deterministic-runbook-coverage-auditor",
            "local_mock_only": True,
            "coverage_score": summary["coverage_score"],
            "readiness_status": summary["readiness_status"],
            "coverage_summary": summary,
            "ticket_mappings": ticket_mappings,
            "runbook_gaps": gaps,
            "owner_assignments": owner_assignments,
            "selected_process_mode": process_mode,
            "role_playbooks": RUNBOOK_ROLE_PLAYBOOKS,
            "delegated_tasks": self._delegated_tasks(gaps, ticket_mappings, process_mode),
            "review_gates": review_gates,
            "artifact_handoffs": artifact_handoffs,
            "run_transparency": self._run_transparency(summary, gaps, review_gates),
            "repo_radar_patterns": RUNBOOK_REPO_RADAR_PATTERNS,
            "endpoint_list": RUNBOOK_COVERAGE_ENDPOINTS,
            "evidence_sources": {
                "active_ticket_count": len(active_tickets),
                "scenario_ticket_count": len(scenario_tickets),
                "playbook_fixture": "sample_data/playbooks.json",
                "kb_fixture": str(self.kb_fixture_path),
                "scenario_fixture": str(self.scenarios_path),
                "artifact_directory": "data/runbook_gap_packs",
            },
            "local_commands": RUNBOOK_COVERAGE_COMMANDS,
            "limitations": self._limitations(),
        }

    async def export_gap_pack(self) -> dict[str, Any]:
        audit = await self.coverage_audit()
        generated_at = datetime.now(timezone.utc)
        pack_id = f"runbook_gap_pack_{generated_at.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        json_path = self.gap_packs_dir / f"{pack_id}.json"
        markdown_path = self.gap_packs_dir / f"{pack_id}.md"
        remediation_tasks = self._remediation_tasks(audit["runbook_gaps"])
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Runbook Coverage Gap Pack",
            "readiness_status": audit["readiness_status"],
            "coverage_score": audit["coverage_score"],
            "coverage_summary": audit["coverage_summary"],
            "ticket_mappings": audit["ticket_mappings"],
            "runbook_gaps": audit["runbook_gaps"],
            "owner_assignments": audit["owner_assignments"],
            "selected_process_mode": audit["selected_process_mode"],
            "role_playbooks": audit["role_playbooks"],
            "delegated_tasks": audit["delegated_tasks"],
            "review_gates": audit["review_gates"],
            "artifact_handoffs": audit["artifact_handoffs"],
            "run_transparency": audit["run_transparency"],
            "repo_radar_patterns": audit["repo_radar_patterns"],
            "remediation_tasks": remediation_tasks,
            "acceptance_criteria": self._acceptance_criteria(),
            "endpoint_list": RUNBOOK_COVERAGE_ENDPOINTS,
            "local_commands": RUNBOOK_COVERAGE_COMMANDS,
            "jd_skills_demonstrated": self._jd_skills(),
            "interviewer_talking_points": self._talking_points(audit),
            "limitations": audit["limitations"],
            "artifact_paths": {
                "runbook_gap_pack_json": str(json_path),
                "runbook_gap_pack_markdown": str(markdown_path),
            },
        }
        markdown = self._markdown(pack)
        self.gap_packs_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        await self.audit.record(
            AuditEvent(
                actor="runbook-coverage",
                action="runbook.gap_pack_exported",
                resource_type="runbook_gap_pack",
                resource_id=pack_id,
                metadata={"markdown_path": str(markdown_path), "json_path": str(json_path)},
            )
        )
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "readiness_status": audit["readiness_status"],
            "coverage_score": audit["coverage_score"],
            "pack": pack,
            "markdown": markdown,
        }

    def _ticket_mapping(
        self,
        ticket: Ticket,
        articles: list[dict[str, Any]],
        playbooks: list[Any],
    ) -> dict[str, Any]:
        ticket_type = self._ticket_type(ticket)
        run_state = {
            "classification": {"category": self._playbook_category(ticket_type)},
            "sla_risk": {
                "level": "high" if ticket.priority in {"urgent", "high"} else "low",
                "reasons": ["runbook coverage audit synthetic context"],
            },
        }
        recommendations = self.playbooks.recommend_for_ticket(ticket, run_state, top_n=3)
        top_runbook = recommendations[0] if recommendations else None
        kb_articles = self._matched_kb_articles(ticket, ticket_type, articles)
        has_dedicated_runbook = any(playbook.category == ticket_type for playbook in playbooks)
        gap_reasons = self._gap_reasons(top_runbook, kb_articles, has_dedicated_runbook, ticket_type)
        coverage_status = self._coverage_status(gap_reasons, top_runbook, kb_articles)
        return {
            "ticket_id": ticket.ticket_id,
            "subject": ticket.subject,
            "source": "scenario_fixture" if ticket.ticket_id.startswith("scenario:") else "ticket_state",
            "customer_tier": ticket.customer_tier,
            "priority": ticket.priority,
            "tags": ticket.tags,
            "ticket_type": ticket_type,
            "coverage_status": coverage_status,
            "kb_coverage": {
                "status": "covered" if kb_articles else "missing",
                "article_ids": [item["article_id"] for item in kb_articles],
                "article_titles": [item["title"] for item in kb_articles],
            },
            "runbook_coverage": {
                "status": "covered"
                if top_runbook and top_runbook.confidence >= RUNBOOK_CONFIDENCE_THRESHOLD and has_dedicated_runbook
                else "gap",
                "dedicated_category_runbook": has_dedicated_runbook,
                "top_runbook_id": top_runbook.id if top_runbook else None,
                "top_runbook_title": top_runbook.title if top_runbook else None,
                "confidence": top_runbook.confidence if top_runbook else 0,
                "owner_roles": top_runbook.owner_roles if top_runbook else [],
                "match_reasons": top_runbook.match_reasons if top_runbook else [],
            },
            "owner": self._owner_for_type(ticket_type),
            "gap_reasons": gap_reasons,
            "recommended_action": self._recommended_action(ticket_type, coverage_status, gap_reasons),
        }

    def _scenario_tickets(self) -> list[Ticket]:
        if not self.scenarios_path.exists():
            return []
        scenarios = self._load_json(self.scenarios_path)
        tickets = []
        for scenario in scenarios:
            ticket = Ticket(
                **TicketCreate(**scenario["ticket"]).model_dump(),
                ticket_id=f"scenario:{scenario['scenario_id']}",
            )
            expected = scenario.get("expected", {})
            ticket.tags = [*ticket.tags, f"expected:{expected.get('classification_category', '')}"]
            tickets.append(ticket)
        return tickets

    def _load_json(self, path: Path) -> list[dict[str, Any]]:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []

    def _ticket_type(self, ticket: Ticket) -> str:
        expected = next((tag.split(":", 1)[1] for tag in ticket.tags if tag.startswith("expected:")), "")
        if expected:
            return self._map_category(expected)
        text = self._normalized_text(ticket)
        scores = {
            category: sum(1 for tag in tags if tag.replace("_", " ") in text or tag in text)
            for category, tags in RUNBOOK_CATEGORY_TAGS.items()
        }
        best = max(scores, key=scores.get)
        return best if scores[best] else "general_support"

    def _normalized_text(self, ticket: Ticket) -> str:
        return re.sub(
            r"[^a-z0-9_ ]+",
            " ",
            f"{ticket.subject} {ticket.body} {' '.join(ticket.tags)}".lower(),
        )

    def _map_category(self, category: str) -> str:
        return {
            "bug": "api_integrations",
            "authentication": "authentication",
            "billing": "billing",
            "api_integrations": "api_integrations",
            "security_privacy": "security_privacy",
            "incident": "incident",
            "how_to": "how_to",
            "general_support": "general_support",
        }.get(category, "general_support")

    def _playbook_category(self, ticket_type: str) -> str:
        if ticket_type in {"incident", "how_to", "general_support"}:
            return ""
        return ticket_type

    def _matched_kb_articles(
        self,
        ticket: Ticket,
        ticket_type: str,
        articles: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        text = self._normalized_text(ticket)
        type_tags = RUNBOOK_CATEGORY_TAGS.get(ticket_type, set())
        matched = []
        for article in articles:
            article_tags = {tag.lower() for tag in article.get("tags", [])}
            tag_hits = sorted(article_tags & type_tags)
            text_hits = sorted(tag for tag in article_tags if tag in text)
            if tag_hits or text_hits:
                matched.append(
                    {
                        "article_id": article["article_id"],
                        "title": article["title"],
                        "tag_hits": list(dict.fromkeys([*tag_hits, *text_hits]))[:6],
                    }
                )
        return matched[:3]

    def _gap_reasons(
        self,
        top_runbook: Any | None,
        kb_articles: list[dict[str, Any]],
        has_dedicated_runbook: bool,
        ticket_type: str,
    ) -> list[str]:
        reasons = []
        if not kb_articles:
            reasons.append("missing_kb_article_mapping")
        if not top_runbook:
            reasons.append("missing_runbook_recommendation")
        elif top_runbook.confidence < RUNBOOK_CONFIDENCE_THRESHOLD:
            reasons.append("low_confidence_runbook_match")
        if not has_dedicated_runbook:
            reasons.append(f"missing_dedicated_{ticket_type}_runbook")
        return reasons

    def _coverage_status(
        self,
        gap_reasons: list[str],
        top_runbook: Any | None,
        kb_articles: list[dict[str, Any]],
    ) -> str:
        if not gap_reasons:
            return "covered"
        if kb_articles or (top_runbook and top_runbook.confidence >= RUNBOOK_CONFIDENCE_THRESHOLD):
            return "partial"
        return "gap"

    def _runbook_gaps(self, mappings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in mappings:
            if item["coverage_status"] != "covered":
                grouped[item["ticket_type"]].append(item)
        gaps = []
        for ticket_type, items in grouped.items():
            reasons = sorted({reason for item in items for reason in item["gap_reasons"]})
            gaps.append(
                {
                    "gap_id": f"runbook_gap_{ticket_type}",
                    "ticket_type": ticket_type,
                    "severity": self._gap_severity(ticket_type, items),
                    "owner": self._owner_for_type(ticket_type),
                    "affected_ticket_count": len(items),
                    "affected_ticket_ids": [item["ticket_id"] for item in items],
                    "gap_reasons": reasons,
                    "recommended_remediation": self._gap_remediation(ticket_type, reasons),
                    "suggested_playbook_outline": self._suggested_playbook_outline(ticket_type),
                    "acceptance_criteria": self._gap_acceptance_criteria(ticket_type),
                }
            )
        return sorted(gaps, key=lambda item: ({"high": 0, "medium": 1, "low": 2}[item["severity"]], item["ticket_type"]))

    def _gap_severity(self, ticket_type: str, items: list[dict[str, Any]]) -> str:
        if ticket_type in HIGH_IMPACT_TYPES or any(item["priority"] in {"urgent", "high"} for item in items):
            return "high"
        if len(items) >= 2 or any(item["customer_tier"] == "enterprise" for item in items):
            return "medium"
        return "low"

    def _owner_assignments(
        self,
        gaps: list[dict[str, Any]],
        mappings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        rows = []
        for owner in sorted({item["owner"] for item in [*gaps, *mappings]}):
            owner_gaps = [gap for gap in gaps if gap["owner"] == owner]
            owner_tickets = [item for item in mappings if item["owner"] == owner]
            rows.append(
                {
                    "owner": owner,
                    "ticket_count": len(owner_tickets),
                    "open_gap_count": len(owner_gaps),
                    "ticket_types": sorted({item["ticket_type"] for item in owner_tickets}),
                    "next_action": self._owner_next_action(owner_gaps),
                }
            )
        return rows

    def _coverage_summary(
        self,
        mappings: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        total = len(mappings) or 1
        counts = {
            status: len([item for item in mappings if item["coverage_status"] == status])
            for status in ["covered", "partial", "gap"]
        }
        score = round(((counts["covered"] + counts["partial"] * 0.5) / total) * 100)
        return {
            "ticket_count": len(mappings),
            "covered_count": counts["covered"],
            "partial_count": counts["partial"],
            "gap_count": counts["gap"],
            "open_runbook_gap_count": len(gaps),
            "coverage_score": score,
            "readiness_status": self._readiness_status(score, gaps),
            "ticket_types": sorted({item["ticket_type"] for item in mappings}),
        }

    def _select_process_mode(
        self,
        summary: dict[str, Any],
        gaps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if any(gap["severity"] == "high" for gap in gaps):
            mode_id = "urgent_gap_remediation"
        elif summary["coverage_score"] < 85 or gaps:
            mode_id = "targeted_backlog"
        else:
            mode_id = "continuous_monitoring"
        return {"mode_id": mode_id, **RUNBOOK_PROCESS_MODES[mode_id]}

    def _delegated_tasks(
        self,
        gaps: list[dict[str, Any]],
        mappings: list[dict[str, Any]],
        process_mode: dict[str, Any],
    ) -> list[dict[str, Any]]:
        tasks = []
        for gap in gaps:
            tasks.append(
                {
                    "task_id": f"{gap['gap_id']}_implementation",
                    "owner_role": gap["owner"],
                    "role_id": self._role_id_for_owner(gap["owner"]),
                    "process_mode": process_mode["mode_id"],
                    "ticket_type": gap["ticket_type"],
                    "status": "blocked_by_missing_runbook"
                    if any(reason.startswith("missing_dedicated") for reason in gap["gap_reasons"])
                    else "ready_for_owner_review",
                    "priority": gap["severity"],
                    "objective": (
                        "Turn coverage gap evidence into a runbook or KB update with "
                        "reviewable acceptance criteria."
                    ),
                    "requirements_to_implementation": {
                        "requirements": gap["gap_reasons"],
                        "implementation_artifact": (
                            "sample_data/playbooks.json or sample_data/kb_articles.json"
                        ),
                        "verification": "GET /runbooks/coverage-audit",
                    },
                    "evidence_refs": gap["affected_ticket_ids"],
                    "acceptance_criteria": gap["acceptance_criteria"],
                }
            )
        if not tasks:
            tasks.append(
                {
                    "task_id": "runbook_continuous_monitoring",
                    "owner_role": "Runbook Program Owner",
                    "role_id": "runbook_program_owner",
                    "process_mode": process_mode["mode_id"],
                    "ticket_type": "all",
                    "status": "ready_for_monitoring",
                    "priority": "low",
                    "objective": "Review fixture changes and keep coverage score above release threshold.",
                    "requirements_to_implementation": {
                        "requirements": [
                            "monitor_new_ticket_types",
                            "preserve_kb_and_runbook_match",
                        ],
                        "implementation_artifact": "sample_data/playbooks.json",
                        "verification": "POST /runbooks/gap-pack",
                    },
                    "evidence_refs": [item["ticket_id"] for item in mappings[:5]],
                    "acceptance_criteria": self._acceptance_criteria(),
                }
            )
        return tasks[: process_mode["max_parallel_owner_tasks"]]

    def _review_gates(
        self,
        summary: dict[str, Any],
        gaps: list[dict[str, Any]],
        mappings: list[dict[str, Any]],
        owner_assignments: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        high_gaps = [gap for gap in gaps if gap["severity"] == "high"]
        kb_missing = [
            item
            for item in mappings
            if item["kb_coverage"]["status"] != "covered"
        ]
        dedicated_runbook_missing = [
            item
            for item in mappings
            if not item["runbook_coverage"]["dedicated_category_runbook"]
        ]
        return [
            self._gate(
                "high_impact_runbook_gate",
                "Escalation Owner",
                not high_gaps,
                f"{len(high_gaps)} high-severity runbook gaps require owner remediation.",
            ),
            self._gate(
                "kb_source_mapping_gate",
                "Knowledge Curator",
                not kb_missing,
                f"{len(kb_missing)} tickets lack KB article mapping.",
            ),
            self._gate(
                "dedicated_runbook_gate",
                "Runbook Program Owner",
                not dedicated_runbook_missing,
                f"{len(dedicated_runbook_missing)} tickets lack dedicated category runbooks.",
            ),
            self._gate(
                "owner_assignment_gate",
                "Operations Reviewer",
                all(item["owner"] and item["next_action"] for item in owner_assignments),
                "Every open gap and ticket type must have an owner and next action.",
            ),
            self._gate(
                "release_threshold_gate",
                "Operations Reviewer",
                summary["coverage_score"] >= 85,
                f"Coverage score is {summary['coverage_score']}; release target is 85.",
            ),
        ]

    def _gate(
        self,
        gate_id: str,
        owner_role: str,
        passed: bool,
        detail: str,
    ) -> dict[str, Any]:
        return {
            "gate_id": gate_id,
            "owner_role": owner_role,
            "status": "pass" if passed else "fail",
            "detail": detail,
            "required_before": "production adapter enablement",
        }

    def _artifact_handoffs(
        self,
        summary: dict[str, Any],
        gaps: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            {
                "artifact": "runbook_coverage_audit",
                "producer": "GET /runbooks/coverage-audit",
                "consumer_role": "Operations Reviewer",
                "evidence": f"{summary['ticket_count']} mapped tickets",
                "handoff_status": "ready",
            },
            {
                "artifact": "runbook_gap_pack",
                "producer": "POST /runbooks/gap-pack",
                "consumer_role": "Runbook Program Owner",
                "evidence": f"{len(gaps)} open runbook gaps",
                "handoff_status": "ready",
            },
            {
                "artifact": "playbook_fixture",
                "producer": "sample_data/playbooks.json",
                "consumer_role": "Escalation Owner",
                "evidence": "local deterministic runbook source",
                "handoff_status": "ready",
            },
            {
                "artifact": "kb_fixture",
                "producer": "sample_data/kb_articles.json",
                "consumer_role": "Knowledge Curator",
                "evidence": "local deterministic KB source",
                "handoff_status": "ready",
            },
            {
                "artifact": "dashboard_panel",
                "producer": "dashboard/streamlit_app.py Runbook Coverage tab",
                "consumer_role": "Operations Reviewer",
                "evidence": "coverage, gates, owners, endpoints, and gap pack export",
                "handoff_status": "ready",
            },
        ]

    def _run_transparency(
        self,
        summary: dict[str, Any],
        gaps: list[dict[str, Any]],
        gates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "execution_mode": "local_deterministic_fixture_audit",
            "external_calls": 0,
            "external_services_blocked": True,
            "ticket_count": summary["ticket_count"],
            "ticket_types": summary["ticket_types"],
            "open_gap_count": len(gaps),
            "failed_gate_count": len([gate for gate in gates if gate["status"] == "fail"]),
            "artifact_directory": "data/runbook_gap_packs",
            "commands_available": len(RUNBOOK_COVERAGE_COMMANDS),
        }

    def _role_id_for_owner(self, owner: str) -> str:
        if "Knowledge" in owner or "Support Enablement" in owner:
            return "kb_curator"
        if owner in {"Incident Commander", "Developer Support Lead", "Security and Compliance Owner"}:
            return "escalation_owner"
        if "QA" in owner:
            return "ops_reviewer"
        return "runbook_program_owner"

    def _readiness_status(self, score: int, gaps: list[dict[str, Any]]) -> str:
        if any(gap["severity"] == "high" for gap in gaps):
            return "gaps_require_owner_remediation"
        if score < 85 or gaps:
            return "review_ready_with_runbook_gaps"
        return "ready_for_operator_handoff"

    def _recommended_action(self, ticket_type: str, status: str, reasons: list[str]) -> str:
        if status == "covered":
            return "Use the recommended playbook and export the run remediation checklist after analysis."
        if any(reason.startswith("missing_dedicated") for reason in reasons):
            return f"Create a dedicated {ticket_type} runbook with owners, checklist, and escalation policy."
        if "missing_kb_article_mapping" in reasons:
            return f"Add or retag KB coverage so {ticket_type} tickets retrieve source guidance."
        return "Review low-confidence playbook matching and adjust tags or checklist coverage."

    def _gap_remediation(self, ticket_type: str, reasons: list[str]) -> list[str]:
        actions = []
        if any(reason.startswith("missing_dedicated") for reason in reasons):
            actions.append(f"Add a dedicated `{ticket_type}` playbook to `sample_data/playbooks.json`.")
        if "missing_kb_article_mapping" in reasons:
            actions.append("Add or retag KB article coverage in `sample_data/kb_articles.json`.")
        if "low_confidence_runbook_match" in reasons:
            actions.append("Add playbook tags that match the observed support ticket language.")
        actions.append("Re-run `GET /runbooks/coverage-audit` and export a fresh gap pack.")
        return actions

    def _suggested_playbook_outline(self, ticket_type: str) -> dict[str, Any]:
        owner = self._owner_for_type(ticket_type)
        return {
            "title": f"{ticket_type.replace('_', ' ').title()} Runbook",
            "category": ticket_type,
            "owner_roles": [owner, "Support Lead", "Customer Success Manager"],
            "minimum_checklist": [
                "Confirm customer impact, scope, severity, and SLA deadline.",
                "Collect evidence needed by the owning team before escalation.",
                "Draft customer-safe status update with next update time.",
                "Record approval state before external or engineering-facing action.",
                "Close the loop with remediation notes and follow-up owner.",
            ],
        }

    def _gap_acceptance_criteria(self, ticket_type: str) -> list[str]:
        return [
            f"At least one playbook has category `{ticket_type}` and owner roles.",
            "Representative tickets map to a runbook with confidence >= 0.45.",
            "Representative tickets map to at least one KB article or source-of-truth snippet.",
            "The dashboard Runbook Coverage panel shows the gap as closed or partial only by design.",
        ]

    def _owner_next_action(self, gaps: list[dict[str, Any]]) -> str:
        if not gaps:
            return "Monitor runbook coverage during future scenario and ticket fixture changes."
        high = [gap for gap in gaps if gap["severity"] == "high"]
        target = high[0] if high else gaps[0]
        return (
            f"Close {target['gap_id']} by adding a dedicated runbook and validating "
            "KB mapping with the coverage audit."
        )

    def _remediation_tasks(self, gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not gaps:
            return [
                {
                    "task_id": "runbook_task_01",
                    "owner": "Support Operations",
                    "priority": "low",
                    "ticket_type": "all",
                    "actions": ["Keep the audit in the demo run and review gaps when fixtures change."],
                }
            ]
        return [
            {
                "task_id": f"runbook_task_{index:02d}",
                "owner": gap["owner"],
                "priority": gap["severity"],
                "ticket_type": gap["ticket_type"],
                "actions": gap["recommended_remediation"],
                "affected_ticket_ids": gap["affected_ticket_ids"],
                "acceptance_criteria": gap["acceptance_criteria"],
            }
            for index, gap in enumerate(gaps, start=1)
        ]

    def _owner_for_type(self, ticket_type: str) -> str:
        return {
            "authentication": "Identity Support Lead",
            "billing": "Billing Operations Lead",
            "api_integrations": "Developer Support Lead",
            "security_privacy": "Security and Compliance Owner",
            "incident": "Incident Commander",
            "how_to": "Support Enablement",
            "general_support": "Support QA Lead",
        }.get(ticket_type, "Support Operations")

    def _acceptance_criteria(self) -> list[str]:
        return [
            "Every high-impact ticket type has a dedicated playbook category and owner roles.",
            "Every active/sample ticket maps to at least one KB article and one runbook recommendation.",
            "Coverage audit score is at least 85 before expanding automation scope.",
            "Gap pack Markdown/JSON is regenerated after playbook or KB fixture changes.",
        ]

    def _jd_skills(self) -> list[str]:
        return [
            "Agentic support governance that separates retrieval coverage from runbook coverage.",
            "FastAPI endpoints with authenticated local/mock enterprise hardening artifacts.",
            "Operational ownership model for support, engineering, compliance, and incident teams.",
            "Deterministic eval/demo output that surfaces coverage gaps without external services.",
            "Dashboard-ready data structures for coverage, gap, owner, endpoint, and artifact review.",
        ]

    def _talking_points(self, audit: dict[str, Any]) -> list[str]:
        summary = audit["coverage_summary"]
        return [
            (
                f"Runbook coverage score is {summary['coverage_score']} across "
                f"{summary['ticket_count']} ticket and scenario fixtures."
            ),
            "The audit shows KB coverage separately from runbook coverage so missing operating procedures are visible.",
            "High-impact incident, security, API, and auth gaps are assigned to explicit operational owners.",
            "The gap pack produces local Markdown/JSON remediation evidence under ignored `data/` artifacts.",
            "The dashboard and demo expose this as reviewer proof without calling Zendesk, Jira, Slack, Azure, or OpenAI.",
        ]

    def _limitations(self) -> list[str]:
        return [
            "Coverage is deterministic over local ticket state, sample scenarios, KB fixtures, and playbooks.",
            "Owner assignments are portfolio defaults, not real team commitments.",
            "The audit does not call external KB, ticketing, Slack, Jira, Azure, OpenAI, or GitHub services.",
            "Runbook confidence is keyword and category based; production ranking would need human validation.",
        ]

    def _markdown(self, pack: dict[str, Any]) -> str:
        summary = pack["coverage_summary"]
        process_mode = pack["selected_process_mode"]
        gap_rows = [
            (
                f"| {gap['gap_id']} | {gap['severity']} | {gap['owner']} | "
                f"{gap['affected_ticket_count']} | {', '.join(gap['gap_reasons'])} |"
            )
            for gap in pack["runbook_gaps"]
        ] or ["| None | none | Support Operations | 0 | No open runbook gaps |"]
        mapping_rows = [
            (
                f"| {item['ticket_id']} | {item['ticket_type']} | {item['coverage_status']} | "
                f"{item['runbook_coverage']['top_runbook_id'] or 'none'} | "
                f"{', '.join(item['kb_coverage']['article_ids']) or 'none'} | {item['owner']} |"
            )
            for item in pack["ticket_mappings"]
        ]
        owner_rows = [
            f"- **{item['owner']}**: {item['open_gap_count']} gaps; {item['next_action']}"
            for item in pack["owner_assignments"]
        ]
        task_rows = [
            (
                f"- {task['task_id']} | {task['priority']} | {task['owner']} | "
                f"{task['ticket_type']}: {'; '.join(task['actions'])}"
            )
            for task in pack["remediation_tasks"]
        ]
        role_rows = [
            (
                f"| {role['role']} | `{role['role_id']}` | {role['mission']} | "
                f"{role['guardrail']} |"
            )
            for role in pack["role_playbooks"]
        ]
        delegation_rows = [
            (
                f"| `{task['task_id']}` | {task['owner_role']} | {task['priority']} | "
                f"{task['status']} | {', '.join(task['evidence_refs']) or 'none'} |"
            )
            for task in pack["delegated_tasks"]
        ]
        gate_rows = [
            f"| `{gate['gate_id']}` | {gate['owner_role']} | {gate['status']} | {gate['detail']} |"
            for gate in pack["review_gates"]
        ]
        handoff_rows = [
            (
                f"| {item['artifact']} | `{item['producer']}` | {item['consumer_role']} | "
                f"{item['evidence']} | {item['handoff_status']} |"
            )
            for item in pack["artifact_handoffs"]
        ]
        pattern_rows = [f"- {pattern}" for pattern in pack["repo_radar_patterns"]]
        endpoints = [f"- `{endpoint}`" for endpoint in pack["endpoint_list"]]
        commands = [f"- `{command}`" for command in pack["local_commands"]]
        skills = [f"- {skill}" for skill in pack["jd_skills_demonstrated"]]
        talking_points = [f"- {point}" for point in pack["interviewer_talking_points"]]
        limitations = [f"- {item}" for item in pack["limitations"]]
        return "\n".join(
            [
                f"# Runbook Coverage Gap Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: {pack['readiness_status']}",
                f"- Coverage score: {pack['coverage_score']}",
                f"- Tickets mapped: {summary['ticket_count']}",
                f"- Covered: {summary['covered_count']}",
                f"- Partial: {summary['partial_count']}",
                f"- Gaps: {summary['gap_count']}",
                "",
                "## Runbook Gaps",
                "| Gap | Severity | Owner | Affected Tickets | Reasons |",
                "| --- | --- | --- | ---: | --- |",
                *gap_rows,
                "",
                "## Ticket Coverage Map",
                "| Ticket | Type | Status | Runbook | KB Articles | Owner |",
                "| --- | --- | --- | --- | --- | --- |",
                *mapping_rows,
                "",
                "## Owner Assignments",
                *owner_rows,
                "",
                "## Remediation Tasks",
                *task_rows,
                "",
                "## Process Mode",
                f"- Mode: `{process_mode['mode_id']}`",
                f"- Cadence: {process_mode['review_cadence']}",
                f"- Max parallel owner tasks: {process_mode['max_parallel_owner_tasks']}",
                f"- Executive review required: {process_mode['requires_executive_review']}",
                f"- Description: {process_mode['description']}",
                "",
                "## Role Playbooks",
                "| Role | Role ID | Mission | Guardrail |",
                "| --- | --- | --- | --- |",
                *role_rows,
                "",
                "## Delegated Coverage Tasks",
                "| Task | Owner | Priority | Status | Evidence |",
                "| --- | --- | --- | --- | --- |",
                *delegation_rows,
                "",
                "## Review Gates",
                "| Gate | Owner | Status | Detail |",
                "| --- | --- | --- | --- |",
                *gate_rows,
                "",
                "## Artifact Handoffs",
                "| Artifact | Producer | Consumer | Evidence | Status |",
                "| --- | --- | --- | --- | --- |",
                *handoff_rows,
                "",
                "## Run Transparency",
                f"- Execution mode: {pack['run_transparency']['execution_mode']}",
                f"- External calls: {pack['run_transparency']['external_calls']}",
                f"- Open gaps: {pack['run_transparency']['open_gap_count']}",
                f"- Failed gates: {pack['run_transparency']['failed_gate_count']}",
                f"- Artifact directory: {pack['run_transparency']['artifact_directory']}",
                "",
                "## Repo Radar Patterns",
                *pattern_rows,
                "",
                "## Endpoint List",
                *endpoints,
                "",
                "## Local Commands",
                *commands,
                "",
                "## JD Skills Demonstrated",
                *skills,
                "",
                "## Interviewer Talking Points",
                *talking_points,
                "",
                "## Limitations",
                *limitations,
                "",
            ]
        )
