"""Load profile for a deployed detector.

Run against a staging deployment, never production. The token is an
identity-fabric credential carrying telemetry:write and threat:read; the
agent id must be one the staging fabric knows:

    export ATD_LOAD_HOST ATD_LOAD_AGENT_TOKEN ATD_LOAD_AGENT_ID   # staging values
    locust -f tests/performance/locustfile.py --host "$ATD_LOAD_HOST" \
           --users 100 --spawn-rate 10 --run-time 10m --headless

Collectors push batches far more often than anyone reads alerts, so the mix
weights batch ingestion over reads. Event ids are unique per request so the
idempotency table does not short-circuit the work.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

from locust import HttpUser, between, task

TOKEN = os.environ.get("ATD_LOAD_AGENT_TOKEN", "")
AGENT = os.environ.get("ATD_LOAD_AGENT_ID", "")
TOOLS = ("ledger.query", "invoice.read", "invoice.match", "payment.schedule")


class CollectorTraffic(HttpUser):
    wait_time = between(0.1, 0.5)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {TOKEN}"}

    @task(10)
    def ingest_batch(self) -> None:
        now = datetime.now(UTC).isoformat()
        batch = [
            {
                "event_id": f"load-{uuid.uuid4().hex}",
                "agent_id": AGENT,
                "timestamp": now,
                "kind": "tool_call",
                "action": TOOLS[i % len(TOOLS)],
                "tool": TOOLS[i % len(TOOLS)],
                "session_id": "load",
            }
            for i in range(50)
        ]
        self.client.post(
            "/v1/events", json={"events": batch}, headers=self._headers(), name="/v1/events"
        )

    @task(1)
    def agent_card(self) -> None:
        self.client.get("/.well-known/agent-card.json", name="/.well-known/agent-card.json")
