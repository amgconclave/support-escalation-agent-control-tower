from pathlib import Path


def _token_headers(client):
    token = client.post("/auth/demo-token").json()["token"]
    return {"X-API-Key": token}


def test_access_matrix_maps_routes_to_roles_and_findings(client):
    headers = _token_headers(client)
    response = client.get("/security/access-matrix", headers=headers)
    assert response.status_code == 200, response.text
    matrix = response.json()

    assert matrix["mode"] == "local-openapi-least-privilege-review"
    assert matrix["local_mock_only"] is True
    assert matrix["summary"]["endpoint_count"] >= 50
    assert matrix["summary"]["protected_endpoint_count"] >= 45
    assert matrix["summary"]["role_count"] >= 6
    assert matrix["summary"]["high_finding_count"] >= 1
    assert matrix["auth_model"]["current_local_auth"] == "single shared demo API key"
    assert any(role["role_id"] == "compliance_officer" for role in matrix["roles"])
    assert any("security/access-review-pack" in command for command in matrix["local_verification_commands"])

    endpoint_rows = {row["endpoint"]: row for row in matrix["access_matrix"]}
    assert "GET /security/access-matrix" in endpoint_rows
    assert "POST /security/access-review-pack" in endpoint_rows
    assert endpoint_rows["POST /security/access-review-pack"]["owner_role"] == "compliance_officer"
    assert (
        "compliance_officer"
        in endpoint_rows["POST /security/access-review-pack"]["allowed_roles"]
    )
    assert endpoint_rows["POST /runs/{run_id}/approve"]["requires_human_approval"] is True


def test_access_review_pack_exports_markdown_and_json(client):
    headers = _token_headers(client)
    response = client.post("/security/access-review-pack", headers=headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]
    markdown = exported["markdown"]

    assert exported["status"] in {"ready_with_local_limitations", "needs_production_authz"}
    assert "access_review_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert "# Access Control Review Pack" in markdown
    assert "## Production Authorization Backlog" in markdown
    assert pack["access_matrix"]["summary"]["least_privilege_score"] >= 50
    assert pack["least_privilege_acceptance_criteria"]
    assert any(item["item"] == "Replace shared demo key" for item in pack["production_authz_backlog"])


def test_access_review_pack_is_listed_in_artifact_inventory(client):
    headers = _token_headers(client)
    client.post("/security/access-review-pack", headers=headers)

    response = client.get("/artifacts/inventory", headers=headers)
    assert response.status_code == 200, response.text
    inventory = response.json()

    row = next(
        item for item in inventory["artifacts"] if item["directory"] == "data/access_review_packs"
    )
    assert row["producer"] == "POST /security/access-review-pack"
    assert row["file_count"] >= 2
    assert "least-privilege roles" in row["reviewer_purpose"]
