import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.routing import APIRoute

from app.core.security import require_api_key
from app.services.launch_checklist import DEMO_KEY, LOCAL_API_BASE


VERIFY_COMMANDS = [
    r".\.venv\Scripts\python.exe -m pytest -q",
    r".\.venv\Scripts\python.exe -m ruff check app tests dashboard scripts",
    r".\.venv\Scripts\python.exe -m app.evals.run_eval",
    r".\.venv\Scripts\python.exe scripts\dashboard_smoke.py",
    r".\.venv\Scripts\python.exe scripts\demo_run.py",
    (
        r'rg "security/access-matrix|security/access-review-pack|Access Control|'
        r'access_review_packs|least privilege" app dashboard docs README.md tests scripts'
    ),
]

ROLE_DEFINITIONS = {
    "support_agent": {
        "label": "Support Agent",
        "purpose": "Triage tickets, inspect workflow evidence, and draft but not approve risky actions.",
        "allowed_domains": {
            "tickets",
            "runs",
            "playbooks",
            "metrics",
            "analytics",
            "customers",
        },
        "can_mutate": {"tickets", "playbooks"},
    },
    "support_lead": {
        "label": "Support Lead",
        "purpose": "Approve customer-facing actions and review queue health.",
        "allowed_domains": {
            "tickets",
            "runs",
            "approvals",
            "policies",
            "handoff",
            "customers",
            "metrics",
            "analytics",
            "ops",
        },
        "can_mutate": {"runs", "policies", "handoff", "customers"},
    },
    "incident_commander": {
        "label": "Incident Commander",
        "purpose": "Own high-SLA, outage, RCA, customer communication, and escalation readiness.",
        "allowed_domains": {
            "runs",
            "replay-lab",
            "drills",
            "incidents",
            "finance",
            "handoff",
            "integrations",
            "ops",
            "metrics",
            "analytics",
        },
        "can_mutate": {"runs", "replay-lab", "drills", "incidents", "finance", "handoff"},
    },
    "engineering_reviewer": {
        "label": "Engineering Reviewer",
        "purpose": "Inspect engineering escalations, trace evidence, outbox payloads, and runbook gaps.",
        "allowed_domains": {
            "runs",
            "integrations",
            "runbooks",
            "knowledge",
            "scenarios",
            "evidence",
            "metrics",
        },
        "can_mutate": {"runbooks", "knowledge", "scenarios"},
    },
    "compliance_officer": {
        "label": "Compliance Officer",
        "purpose": "Review audit events, evidence custody, data residency, and access controls.",
        "allowed_domains": {
            "audit",
            "compliance",
            "evidence",
            "security",
            "api",
            "artifacts",
            "ui",
        },
        "can_mutate": {"compliance", "evidence", "security"},
    },
    "platform_admin": {
        "label": "Platform Admin",
        "purpose": "Operate local demo/runtime/release surfaces and export reviewer packs.",
        "allowed_domains": {
            "all",
        },
        "can_mutate": {"all"},
    },
    "read_only_reviewer": {
        "label": "Read-Only Reviewer",
        "purpose": "Inspect public health/readiness and non-mutating local proof endpoints.",
        "allowed_domains": {
            "health",
            "runtime",
            "reviewer",
            "portfolio",
            "release",
            "api",
            "artifacts",
            "ui",
            "security",
        },
        "can_mutate": set(),
    },
}

MUTATING_SAFE_EXPORT_PREFIXES = (
    "/artifacts/",
    "/api/",
    "/ui/",
    "/reviewer/",
    "/portfolio/",
    "/release/",
    "/runtime/",
    "/security/",
)

PUBLIC_ENDPOINTS = {
    "GET /health",
    "POST /auth/demo-token",
    "GET /runtime/demo-readiness",
}

HIGH_RISK_PATH_TOKENS = {
    "approve",
    "reject",
    "outbox",
    "compliance",
    "data-residency",
    "finance",
    "policies",
    "git",
    "audit",
    "integrations",
}


class AccessControlService:
    """Local least-privilege workbench for protected API surfaces."""

    def __init__(self, access_review_dir: Path):
        self.access_review_dir = access_review_dir
        self.data_root = access_review_dir.parent

    async def matrix(self, app: Any) -> dict[str, Any]:
        return self.matrix_sync(app)

    async def export_review_pack(self, app: Any) -> dict[str, Any]:
        matrix = self.matrix_sync(app)
        generated_at = datetime.now(timezone.utc)
        pack_id = f"access_review_{generated_at.strftime('%Y%m%d_%H%M%S')}"
        json_path = self.access_review_dir / f"{pack_id}.json"
        markdown_path = self.access_review_dir / f"{pack_id}.md"
        pack = {
            "pack_id": pack_id,
            "generated_at": generated_at.isoformat(),
            "title": "Access Control Review Pack",
            "access_matrix": matrix,
            "least_privilege_acceptance_criteria": self._acceptance_criteria(matrix),
            "production_authz_backlog": self._production_backlog(matrix),
            "reviewer_walkthrough": self._reviewer_walkthrough(),
            "local_verification_commands": VERIFY_COMMANDS,
            "artifact_paths": {
                "access_review_markdown": str(markdown_path),
                "access_review_json": str(json_path),
            },
        }
        markdown = self._markdown(pack)
        self.access_review_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
        markdown_path.write_text(markdown, encoding="utf-8")
        return {
            "pack_id": pack_id,
            "format": "markdown+json",
            "status": matrix["status"],
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "summary": matrix["summary"],
            "pack": pack,
            "markdown": markdown,
        }

    def matrix_sync(self, app: Any) -> dict[str, Any]:
        generated_at = datetime.now(timezone.utc)
        routes = self._route_inventory(app)
        access_rows = [self._access_row(row) for row in routes]
        findings = self._findings(routes, access_rows)
        summary = self._summary(routes, access_rows, findings)
        return {
            "generated_at": generated_at.isoformat(),
            "title": "Access Control Matrix",
            "status": "needs_production_authz" if findings["critical"] else "ready_with_local_limitations",
            "mode": "local-openapi-least-privilege-review",
            "local_mock_only": True,
            "summary": summary,
            "auth_model": self._auth_model(),
            "roles": self._roles(),
            "domain_ownership": self._domain_ownership(access_rows),
            "access_matrix": access_rows,
            "findings": findings,
            "sample_commands": self._sample_commands(),
            "local_verification_commands": VERIFY_COMMANDS,
            "limitations": self._limitations(),
        }

    def _route_inventory(self, app: Any) -> list[dict[str, Any]]:
        openapi = app.openapi()
        protected = self._protected_route_keys(app)
        rows = []
        for path, operations in openapi.get("paths", {}).items():
            for method, operation in operations.items():
                method_name = method.upper()
                if method_name not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                endpoint = f"{method_name} {path}"
                rows.append(
                    {
                        "method": method_name,
                        "path": path,
                        "endpoint": endpoint,
                        "domain": self._domain(path),
                        "operation_id": operation.get("operationId", ""),
                        "requires_api_key": (method_name, path) in protected,
                    }
                )
        return sorted(rows, key=lambda row: (row["domain"], row["path"], row["method"]))

    def _protected_route_keys(self, app: Any) -> set[tuple[str, str]]:
        keys = set()
        for route in getattr(app, "routes", []):
            if not isinstance(route, APIRoute):
                continue
            if not self._route_requires_api_key(route):
                continue
            for method in route.methods or set():
                if method not in {"HEAD", "OPTIONS"}:
                    keys.add((method, route.path))
        return keys

    def _route_requires_api_key(self, route: APIRoute) -> bool:
        dependency_calls = [dependency.call for dependency in route.dependant.dependencies]
        return require_api_key in dependency_calls or any(
            getattr(call, "__name__", "") == "require_api_key" for call in dependency_calls
        )

    def _access_row(self, row: dict[str, Any]) -> dict[str, Any]:
        sensitivity = self._sensitivity(row)
        allowed_roles = self._allowed_roles(row)
        owner_role = self._owner_role(row["domain"], allowed_roles)
        return {
            **row,
            "sensitivity": sensitivity,
            "owner_role": owner_role,
            "allowed_roles": allowed_roles,
            "requires_human_approval": self._requires_human_approval(row, sensitivity),
            "production_scope": self._production_scope(row, sensitivity),
            "data_exposure": self._data_exposure(row, sensitivity),
            "least_privilege_note": self._least_privilege_note(row, allowed_roles),
        }

    def _allowed_roles(self, row: dict[str, Any]) -> list[str]:
        domain = row["domain"]
        method = row["method"]
        roles = []
        for role_id, definition in ROLE_DEFINITIONS.items():
            allowed_domains = definition["allowed_domains"]
            can_mutate = definition["can_mutate"]
            domain_allowed = "all" in allowed_domains or domain in allowed_domains
            if not domain_allowed:
                continue
            if method != "GET" and "all" not in can_mutate and domain not in can_mutate:
                continue
            roles.append(role_id)
        if row["endpoint"] in PUBLIC_ENDPOINTS and "read_only_reviewer" not in roles:
            roles.append("read_only_reviewer")
        return sorted(roles)

    def _owner_role(self, domain: str, allowed_roles: list[str]) -> str:
        preferred = {
            "compliance": "compliance_officer",
            "evidence": "compliance_officer",
            "audit": "compliance_officer",
            "security": "compliance_officer",
            "incidents": "incident_commander",
            "finance": "incident_commander",
            "handoff": "incident_commander",
            "runbooks": "engineering_reviewer",
            "knowledge": "engineering_reviewer",
            "integrations": "engineering_reviewer",
            "policies": "support_lead",
            "approvals": "support_lead",
        }.get(domain)
        if preferred and preferred in allowed_roles:
            return preferred
        if "platform_admin" in allowed_roles:
            return "platform_admin"
        return allowed_roles[0] if allowed_roles else "unassigned"

    def _sensitivity(self, row: dict[str, Any]) -> str:
        if row["endpoint"] in PUBLIC_ENDPOINTS:
            return "public_local_demo"
        tokens = set(row["path"].strip("/").replace("-", "_").replace("{", "").replace("}", "").split("/"))
        token_text = " ".join(tokens).replace("_", "-")
        if row["method"] != "GET" and any(row["path"].startswith(prefix) for prefix in MUTATING_SAFE_EXPORT_PREFIXES):
            return "medium_export"
        if row["method"] != "GET":
            return "high_mutation"
        if any(token in token_text for token in HIGH_RISK_PATH_TOKENS):
            return "high_read"
        return "medium_read"

    def _requires_human_approval(self, row: dict[str, Any], sensitivity: str) -> bool:
        if row["path"].endswith(("/approve", "/reject")):
            return True
        return sensitivity in {"high_mutation", "high_read"} and row["domain"] in {
            "integrations",
            "policies",
            "compliance",
            "finance",
            "git",
            "audit",
        }

    def _production_scope(self, row: dict[str, Any], sensitivity: str) -> str:
        suffix = "read" if row["method"] == "GET" else "write"
        if sensitivity.startswith("high"):
            suffix = "approve" if row["path"].endswith(("/approve", "/reject")) else suffix
        return f"control_tower:{row['domain']}:{suffix}"

    def _data_exposure(self, row: dict[str, Any], sensitivity: str) -> str:
        if row["endpoint"] in PUBLIC_ENDPOINTS:
            return "No customer payload; local health/token/readiness only."
        if row["domain"] in {"compliance", "evidence", "audit", "integrations", "finance"}:
            return "May expose customer, approval, outbox, audit, or financial-risk evidence."
        if sensitivity == "high_mutation":
            return "Can create or change operational artifacts or approval state."
        return "May expose ticket, run, trace, metric, or generated-artifact metadata."

    def _least_privilege_note(self, row: dict[str, Any], allowed_roles: list[str]) -> str:
        if row["endpoint"] in PUBLIC_ENDPOINTS:
            return "Public by design for local demo bootstrap; keep response non-sensitive."
        if not allowed_roles:
            return "No proposed role owns this endpoint; add owner before production auth."
        if row["method"] != "GET":
            return "Write/export action; require scoped token plus audit trail in production."
        return "Read action; allow only role-scoped inspection of local support evidence."

    def _findings(
        self,
        routes: list[dict[str, Any]],
        access_rows: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        public_sensitive = [
            {
                "severity": "critical",
                "endpoint": row["endpoint"],
                "finding": "Endpoint is public but not in the approved local bootstrap allowlist.",
                "recommended_action": "Add API-key protection or remove sensitive payloads.",
            }
            for row in routes
            if not row["requires_api_key"] and row["endpoint"] not in PUBLIC_ENDPOINTS
        ]
        broad_admin = [
            {
                "severity": "medium",
                "endpoint": row["endpoint"],
                "finding": "Only platform_admin currently owns this endpoint in the proposed matrix.",
                "recommended_action": "Decide whether a narrower business owner should be added.",
            }
            for row in access_rows
            if row["allowed_roles"] == ["platform_admin"] and row["endpoint"] not in PUBLIC_ENDPOINTS
        ]
        single_key = [
            {
                "severity": "high",
                "endpoint": "all protected endpoints",
                "finding": "Local runtime still uses one demo API key; role scopes are advisory evidence.",
                "recommended_action": "Before production, replace the demo key with per-role scoped tokens or IdP claims.",
            }
        ]
        approval_edges = [
            {
                "severity": "medium",
                "endpoint": row["endpoint"],
                "finding": "Approval/state-changing endpoint needs explicit approver role and audit review.",
                "recommended_action": "Keep support_lead or incident_commander approval plus audit evidence.",
            }
            for row in access_rows
            if row["requires_human_approval"]
        ]
        unassigned = [
            {
                "severity": "critical",
                "endpoint": row["endpoint"],
                "finding": "No least-privilege owner role was assigned.",
                "recommended_action": "Assign a role or block the endpoint before production.",
            }
            for row in access_rows
            if not row["allowed_roles"]
        ]
        return {
            "critical": [*public_sensitive, *unassigned],
            "high": single_key,
            "medium": [*broad_admin, *approval_edges],
            "low": [
                {
                    "severity": "low",
                    "endpoint": "POST /auth/demo-token",
                    "finding": "Demo token endpoint is public for local bootstrap.",
                    "recommended_action": "Keep it disabled or protected outside local portfolio mode.",
                }
            ],
        }

    def _summary(
        self,
        routes: list[dict[str, Any]],
        access_rows: list[dict[str, Any]],
        findings: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        protected_count = len([row for row in routes if row["requires_api_key"]])
        role_counts = Counter(role for row in access_rows for role in row["allowed_roles"])
        sensitivity_counts = Counter(row["sensitivity"] for row in access_rows)
        return {
            "endpoint_count": len(routes),
            "protected_endpoint_count": protected_count,
            "public_endpoint_count": len(routes) - protected_count,
            "role_count": len(ROLE_DEFINITIONS),
            "critical_finding_count": len(findings["critical"]),
            "high_finding_count": len(findings["high"]),
            "medium_finding_count": len(findings["medium"]),
            "sensitivity_counts": dict(sorted(sensitivity_counts.items())),
            "role_endpoint_counts": dict(sorted(role_counts.items())),
            "least_privilege_score": self._score(routes, findings),
        }

    def _score(self, routes: list[dict[str, Any]], findings: dict[str, list[dict[str, Any]]]) -> int:
        score = 100
        score -= len(findings["critical"]) * 20
        score -= len(findings["high"]) * 10
        score -= min(len(findings["medium"]) * 2, 20)
        if not routes:
            score = 0
        return max(score, 0)

    def _auth_model(self) -> dict[str, Any]:
        return {
            "current_local_auth": "single shared demo API key",
            "header": "X-API-Key",
            "bearer_alternative": f"Authorization: Bearer {DEMO_KEY}",
            "demo_token_endpoint": "POST /auth/demo-token",
            "recommended_production_model": [
                "Issue per-role scoped tokens or map IdP claims to the production_scope values.",
                "Keep /health public but disable public demo-token minting outside local mode.",
                "Attach actor, role, scope, trace_id, and approval_id to every audit event.",
            ],
        }

    def _roles(self) -> list[dict[str, Any]]:
        return [
            {
                "role_id": role_id,
                "label": definition["label"],
                "purpose": definition["purpose"],
                "allowed_domains": sorted(definition["allowed_domains"]),
                "write_domains": sorted(definition["can_mutate"]),
            }
            for role_id, definition in ROLE_DEFINITIONS.items()
        ]

    def _domain_ownership(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            grouped[row["domain"]].append(row)
        ownership = []
        for domain, domain_rows in sorted(grouped.items()):
            owners = Counter(row["owner_role"] for row in domain_rows)
            ownership.append(
                {
                    "domain": domain,
                    "endpoint_count": len(domain_rows),
                    "primary_owner_role": owners.most_common(1)[0][0],
                    "mutating_endpoint_count": len([row for row in domain_rows if row["method"] != "GET"]),
                    "high_sensitivity_count": len(
                        [row for row in domain_rows if row["sensitivity"].startswith("high")]
                    ),
                }
            )
        return ownership

    def _acceptance_criteria(self, matrix: dict[str, Any]) -> list[str]:
        return [
            "Every non-public endpoint has API-key protection in local mode.",
            "Every endpoint maps to at least one least-privilege owner role.",
            "Production auth maps IdP role/scope claims to `production_scope` before real adapters are enabled.",
            "Approval, outbox, compliance, finance, and policy endpoints retain audit evidence with actor identity.",
            (
                "The high finding for the shared demo key is closed before non-local deployment; "
                f"current score is {matrix['summary']['least_privilege_score']}."
            ),
        ]

    def _production_backlog(self, matrix: dict[str, Any]) -> list[dict[str, str]]:
        return [
            {
                "item": "Replace shared demo key",
                "owner_role": "platform_admin",
                "acceptance": "Use per-role scoped tokens or IdP claims instead of the local demo key.",
            },
            {
                "item": "Enforce route scopes",
                "owner_role": "platform_admin",
                "acceptance": "FastAPI dependency validates `production_scope` for each protected endpoint.",
            },
            {
                "item": "Bind approvals to identities",
                "owner_role": "support_lead",
                "acceptance": "Approval audit events include actor, role, ticket, run, approval ID, and trace ID.",
            },
            {
                "item": "Review compliance exports",
                "owner_role": "compliance_officer",
                "acceptance": "Data residency, evidence, and audit exports are available only to compliance scopes.",
            },
            {
                "item": "Close critical findings",
                "owner_role": "platform_admin",
                "acceptance": f"Critical finding count is {matrix['summary']['critical_finding_count']} before launch.",
            },
        ]

    def _reviewer_walkthrough(self) -> list[dict[str, str]]:
        return [
            {
                "step": "Fetch matrix",
                "command": (
                    "Invoke-RestMethod -Method Get "
                    f"-Uri {LOCAL_API_BASE}/security/access-matrix "
                    f"-Headers @{{'X-API-Key'='{DEMO_KEY}'}}"
                ),
            },
            {
                "step": "Export pack",
                "command": (
                    "Invoke-RestMethod -Method Post "
                    f"-Uri {LOCAL_API_BASE}/security/access-review-pack "
                    f"-Headers @{{'X-API-Key'='{DEMO_KEY}'}}"
                ),
            },
            {
                "step": "Inspect findings",
                "command": "Review `findings.high` and `least_privilege_acceptance_criteria` in the JSON pack.",
            },
        ]

    def _sample_commands(self) -> dict[str, str]:
        return {
            "access_matrix": (
                "Invoke-RestMethod -Method Get "
                f"-Uri {LOCAL_API_BASE}/security/access-matrix "
                f"-Headers @{{'X-API-Key'='{DEMO_KEY}'}}"
            ),
            "access_review_pack": (
                "Invoke-RestMethod -Method Post "
                f"-Uri {LOCAL_API_BASE}/security/access-review-pack "
                f"-Headers @{{'X-API-Key'='{DEMO_KEY}'}}"
            ),
        }

    def _limitations(self) -> list[str]:
        return [
            "This is a deterministic local authorization review, not production RBAC enforcement.",
            "The current runtime still accepts one demo API key for protected endpoints.",
            "Endpoint inventory is derived from local FastAPI/OpenAPI metadata.",
            "Generated access review artifacts under data/access_review_packs are ignored local proof.",
            "No Azure, OpenAI, IdP, gateway, WAF, Zendesk, Jira, Slack, GitHub, or external service is called.",
        ]

    def _domain(self, path: str) -> str:
        parts = [part for part in path.split("/") if part and not part.startswith("{")]
        return parts[0] if parts else "root"

    def _markdown(self, pack: dict[str, Any]) -> str:
        matrix = pack["access_matrix"]
        summary = matrix["summary"]
        role_rows = [
            (
                f"| {role['role_id']} | {role['label']} | "
                f"{', '.join(role['allowed_domains'])} | {', '.join(role['write_domains']) or 'none'} |"
            )
            for role in matrix["roles"]
        ]
        domain_rows = [
            (
                f"| {row['domain']} | {row['endpoint_count']} | {row['primary_owner_role']} | "
                f"{row['mutating_endpoint_count']} | {row['high_sensitivity_count']} |"
            )
            for row in matrix["domain_ownership"]
        ]
        access_rows = [
            (
                f"| `{row['endpoint']}` | {row['sensitivity']} | {row['owner_role']} | "
                f"{', '.join(row['allowed_roles']) or 'none'} | `{row['production_scope']}` |"
            )
            for row in matrix["access_matrix"]
        ]
        finding_rows = [
            f"- **{severity.upper()}** `{item['endpoint']}`: {item['finding']}"
            for severity, rows in matrix["findings"].items()
            for item in rows
        ]
        criteria_rows = [f"- [ ] {item}" for item in pack["least_privilege_acceptance_criteria"]]
        backlog_rows = [
            f"- **{item['item']}** ({item['owner_role']}): {item['acceptance']}"
            for item in pack["production_authz_backlog"]
        ]
        command_rows = [f"- `{command}`" for command in pack["local_verification_commands"]]
        limitation_rows = [f"- {item}" for item in matrix["limitations"]]
        return "\n".join(
            [
                f"# Access Control Review Pack: {pack['pack_id']}",
                "",
                "## Summary",
                f"- Status: **{matrix['status']}**",
                f"- Endpoints: {summary['endpoint_count']}",
                f"- Protected endpoints: {summary['protected_endpoint_count']}",
                f"- Public endpoints: {summary['public_endpoint_count']}",
                f"- Least-privilege score: {summary['least_privilege_score']}",
                f"- Critical findings: {summary['critical_finding_count']}",
                f"- High findings: {summary['high_finding_count']}",
                "",
                "## Role Matrix",
                "| Role | Label | Read Domains | Write Domains |",
                "| --- | --- | --- | --- |",
                *role_rows,
                "",
                "## Domain Ownership",
                "| Domain | Endpoints | Owner | Mutating | High Sensitivity |",
                "| --- | --- | --- | --- | --- |",
                *domain_rows,
                "",
                "## Endpoint Access Matrix",
                "| Endpoint | Sensitivity | Owner | Allowed Roles | Production Scope |",
                "| --- | --- | --- | --- | --- |",
                *access_rows,
                "",
                "## Findings",
                *finding_rows,
                "",
                "## Least Privilege Acceptance Criteria",
                *criteria_rows,
                "",
                "## Production Authorization Backlog",
                *backlog_rows,
                "",
                "## Local Verification Commands",
                *command_rows,
                "",
                "## Limitations",
                *limitation_rows,
                "",
            ]
        )
