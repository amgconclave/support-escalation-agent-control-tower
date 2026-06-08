from pathlib import Path
import sys

import requests
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import create_app  # noqa: E402


BASE = "http://localhost:8000"
DEMO_TICKET = {
    "subject": "Enterprise SSO outage blocking all agents",
    "body": "Our enterprise agents cannot log in with SAML SSO. Production outage and SLA breach risk.",
    "priority": "urgent",
    "customer_tier": "enterprise",
    "tags": ["auth", "sso", "outage"],
}


def run_with_http_server() -> dict | None:
    try:
        token_payload = requests.post(f"{BASE}/auth/demo-token", timeout=3).json()
        token = token_payload.get("access_token") or token_payload["token"]
        headers = {"x-api-key": token}
        ticket = requests.post(
            f"{BASE}/tickets/ingest",
            headers=headers,
            json=DEMO_TICKET,
            timeout=10,
        ).json()
        if "ticket_id" not in ticket:
            return None
        run = requests.post(
            f"{BASE}/tickets/{ticket['ticket_id']}/analyze",
            headers=headers,
            timeout=20,
        ).json()
        if "run_id" not in run:
            return None
        return {"ticket": ticket, "run": run, "mode": "http"}
    except Exception:
        return None


def run_in_process() -> dict:
    app = create_app()
    with TestClient(app) as client:
        token_payload = client.post("/auth/demo-token").json()
        token = token_payload.get("access_token") or token_payload["token"]
        headers = {"x-api-key": token}
        ticket = client.post("/tickets/ingest", headers=headers, json=DEMO_TICKET).json()
        run = client.post(f"/tickets/{ticket['ticket_id']}/analyze", headers=headers).json()
        return {"ticket": ticket, "run": run, "mode": "in-process"}


def main():
    result = run_with_http_server() or run_in_process()
    ticket = result["ticket"]
    run = result["run"]
    print("Mode:", result["mode"])
    print("Ticket:", ticket["ticket_id"])
    print("Run:", run["run_id"], run["status"], run["final_action"])
    print("Approval:", run["state"].get("approval_id"))


if __name__ == "__main__":
    main()
