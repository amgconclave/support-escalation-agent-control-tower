from pathlib import Path


def _token_headers(client):
    token = client.post("/auth/demo-token").json()["token"]
    return {"X-API-Key": token}


def _rollout_payload() -> dict:
    return {
        "process_mode": "canary",
        "max_new_auto_allowed": 0,
        "max_sla_regressions": 0,
        "max_change_risk_score": 30,
        "proposed": {
            "confidence_cutoff": 0.72,
            "sla_high_risk_threshold": 0.65,
            "auto_approval_max_blast_radius": 25,
        },
        "scenario_limit": 6,
    }


def test_policy_rollout_plan_builds_fail_closed_review_gate(client):
    headers = _token_headers(client)
    response = client.post("/policies/rollout-plan", headers=headers, json=_rollout_payload())

    assert response.status_code == 200, response.text
    plan = response.json()
    summary = plan["summary"]

    assert plan["title"] == "Policy Rollout Review Gate"
    assert plan["local_mock_only"] is True
    assert plan["process_mode"] == "canary"
    assert plan["status"] in {"ready", "pilot_only", "blocked"}
    assert summary["scenario_count"] == 6
    assert len(plan["review_gates"]) == 4
    assert {gate["gate_id"] for gate in plan["review_gates"]} == {
        "new_auto_allowed_budget",
        "sla_regression_budget",
        "blast_radius_budget",
        "manual_review_capacity",
    }
    assert any(phase["phase"] == "support_lead_canary" for phase in plan["canary_rollout"])
    assert {item["role"] for item in plan["role_signoffs"]} >= {
        "Support Lead",
        "Policy Admin",
    }
    assert "run transparency" in plan["repo_radar_patterns"]
    assert any("policies/rollout-pack" in command for command in plan["local_commands"])


def test_policy_rollout_pack_exports_artifacts_and_audit_event(client):
    headers = _token_headers(client)
    response = client.post("/policies/rollout-pack", headers=headers, json=_rollout_payload())

    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert "policy_rollout_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["title"] == "Policy Rollout Review Pack"
    assert "canary_rollout" in pack["rollout_plan"]
    assert "Policy Rollout Review Pack" in exported["markdown"]
    assert "rollback trigger" in " ".join(pack["local_commands"]).lower()

    audit = client.get("/audit/events", headers=headers).json()
    assert any(
        event["action"] == "policy.rollout_pack_exported"
        for event in audit
    )


def test_policy_rollout_is_registered_for_dashboard_and_artifacts(client):
    headers = _token_headers(client)
    client.post("/policies/rollout-pack", headers=headers, json=_rollout_payload())

    inventory = client.get("/artifacts/inventory", headers=headers).json()
    row = next(
        item for item in inventory["artifacts"] if item["directory"] == "data/policy_rollout_packs"
    )
    assert row["producer"] == "POST /policies/rollout-pack"
    assert row["file_count"] >= 2
    assert "role signoffs" in row["reviewer_purpose"]

    smoke = client.get("/ui/dashboard-smoke", headers=headers).json()
    assert smoke["status"] == "pass"
    endpoint_refs = {item["endpoint"] for item in smoke["endpoint_references"]}
    assert "POST /policies/rollout-plan" in endpoint_refs
    assert "POST /policies/rollout-pack" in endpoint_refs
    assert any(
        item["producer_endpoint"] == "POST /policies/rollout-pack"
        and item["artifact_directory"] == "data/policy_rollout_packs"
        for item in smoke["generated_artifact_tabs"]
    )
