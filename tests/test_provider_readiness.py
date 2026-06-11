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


def test_provider_readiness_reports_real_adapter_classes(client):
    headers = _headers(client)

    response = client.get("/providers/readiness", headers=headers)
    assert response.status_code == 200, response.text
    readiness = response.json()

    classes = {item["provider"]: item["runtime_class"] for item in readiness["provider_matrix"]}
    assert classes["openai"] == "OpenAIChatProvider+LocalMockFallback"
    assert classes["azure_openai"] == "AzureOpenAIChatProvider+LocalMockFallback"
    assert "placeholder" not in " ".join(classes.values()).lower()


def test_azure_provider_selection_requires_deployment(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example-resource.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "redacted-test-key")
    monkeypatch.delenv("AZURE_OPENAI_DEPLOYMENT", raising=False)
    monkeypatch.delenv("CONTROL_TOWER_AZURE_OPENAI_DEPLOYMENT", raising=False)
    app = create_app(
        Settings(
            state_file=tmp_path / "state.json",
            api_keys="test-key",
            demo_api_key="test-key",
            llm_provider="azure_openai",
        )
    )

    with TestClient(app) as client:
        response = client.get("/providers/readiness", headers=_headers(client))
        assert response.status_code == 200, response.text
        readiness = response.json()

    assert readiness["readiness_status"] == "external_provider_blocked"
    assert any(
        item["check_id"] == "azure_credentials_present_if_selected" and item["status"] == "fail"
        for item in readiness["provider_checks"]
    )


def test_workflow_falls_back_to_local_when_openai_selected_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CONTROL_TOWER_OPENAI_API_KEY", raising=False)
    app = create_app(
        Settings(
            state_file=tmp_path / "state.json",
            api_keys="test-key",
            demo_api_key="test-key",
            llm_provider="openai",
        )
    )

    with TestClient(app) as client:
        headers = _headers(client)
        ingest = client.post(
            "/tickets/ingest",
            headers=headers,
            json={
                "subject": "Production webhook 500 regression",
                "body": "Enterprise webhook traffic returns 500s and blocks production order ingestion.",
                "priority": "urgent",
                "customer_tier": "enterprise",
                "tags": ["webhook", "api"],
            },
        )
        assert ingest.status_code == 200, ingest.text
        run = client.post(f"/tickets/{ingest.json()['ticket_id']}/analyze", headers=headers)
        assert run.status_code == 200, run.text
        state = run.json()["state"]

    provider_events = state["llm_provider_events"]
    assert provider_events
    assert all(event["provider"] == "local" for event in provider_events)
    assert any(event["fallback_used"] for event in provider_events)
    assert "API key" in provider_events[0]["fallback_reason"]


def test_readiness_stays_structured_when_fallback_disabled_and_provider_missing_key(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CONTROL_TOWER_OPENAI_API_KEY", raising=False)
    app = create_app(
        Settings(
            state_file=tmp_path / "state.json",
            api_keys="test-key",
            demo_api_key="test-key",
            llm_provider="openai",
            llm_fallback_enabled=False,
        )
    )

    with TestClient(app) as client:
        response = client.get("/providers/readiness", headers=_headers(client))
        assert response.status_code == 200, response.text
        readiness = response.json()

    assert readiness["active_provider_class"] == "ProviderConfigBlocked"
    assert readiness["readiness_status"] == "external_provider_blocked"
