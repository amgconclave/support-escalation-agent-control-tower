from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def _headers(client):
    token = client.post("/auth/demo-token").json()["token"]
    return {"X-API-Key": token}


def test_provider_readiness_reports_local_default_without_secret_values(client):
    headers = _headers(client)

    response = client.get("/providers/readiness", headers=headers)
    assert response.status_code == 200, response.text
    readiness = response.json()

    assert readiness["mode"] == "local-deterministic-provider-readiness"
    assert readiness["configured_provider"] == "local"
    assert readiness["active_provider_class"] == "LocalMockLlmProvider"
    assert readiness["local_mock_only"] is True
    assert readiness["readiness_status"] == "local_mock_ready"
    assert readiness["summary"]["external_services_required_for_default_demo"] is False
    assert readiness["summary"]["secrets_exposed"] is False
    assert "GET /providers/readiness" in readiness["endpoint_list"]
    assert "POST /providers/readiness-pack" in readiness["endpoint_list"]
    assert any(item["provider"] == "local" and item["status"] == "ready" for item in readiness["provider_matrix"])
    assert all(item["value"] in {"", "redacted"} for item in readiness["env_presence"]["variables"])


def test_provider_readiness_pack_exports_activation_artifacts(client):
    headers = _headers(client)

    response = client.post("/providers/readiness-pack", headers=headers)
    assert response.status_code == 200, response.text
    exported = response.json()
    pack = exported["pack"]

    assert exported["readiness_status"] == "local_mock_ready"
    assert "provider_readiness_packs" in exported["markdown_path"]
    assert Path(exported["markdown_path"]).exists()
    assert Path(exported["json_path"]).exists()
    assert pack["provider_readiness"]["summary"]["secrets_exposed"] is False
    assert pack["activation_checklist"]
    assert pack["acceptance_criteria"]
    assert "POST /providers/readiness-pack" in pack["endpoint_list"]
    assert "# Provider Readiness Guard Pack" in exported["markdown"]


def test_provider_readiness_fails_closed_for_unsupported_provider(tmp_path):
    app = create_app(
        Settings(
            state_file=tmp_path / "state.json",
            api_keys="test-key",
            demo_api_key="test-key",
            llm_provider="unsupported-live-provider",
        )
    )

    with TestClient(app) as client:
        response = client.get("/providers/readiness", headers=_headers(client))
        assert response.status_code == 200, response.text
        readiness = response.json()

    assert readiness["readiness_status"] == "external_provider_blocked"
    assert readiness["summary"]["fail_count"] >= 1
    assert any(
        item["check_id"] == "provider_supported" and item["status"] == "fail"
        for item in readiness["provider_checks"]
    )
