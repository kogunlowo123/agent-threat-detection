"""SIEM output: OCSF 1.3 Detection Finding (class 2004) records, delivered from an outbox.

Findings are written to the ``siem_outbox`` table in the same transaction as
the alert they describe, then delivered by ``SiemDispatcher`` with retry and
exponential back-off. A SIEM outage therefore delays findings but never
loses them, and never blocks ingestion.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime, timedelta
from enum import IntEnum
from pathlib import Path
from typing import Any, Protocol

import httpx
from agentic_core.observability import get_logger

from agent_threat_detection import __version__
from agent_threat_detection.domain.findings import Alert, AlertStatus, Severity
from agent_threat_detection.infrastructure.database import OutboxItem, ThreatStore

OCSF_VERSION = "1.3.0"
ATTACK_VERSION = "16.1"
log = get_logger("agent_threat_detection.siem")


class Activity(IntEnum):
    CREATE = 1
    UPDATE = 2
    CLOSE = 3


_SEVERITY = {
    Severity.INFORMATIONAL: (1, "Informational"),
    Severity.LOW: (2, "Low"),
    Severity.MEDIUM: (3, "Medium"),
    Severity.HIGH: (4, "High"),
    Severity.CRITICAL: (5, "Critical"),
}
_STATUS = {
    AlertStatus.NEW: (1, "New"),
    AlertStatus.ACKNOWLEDGED: (2, "In Progress"),
    AlertStatus.CONTAINED: (2, "In Progress"),
    AlertStatus.FALSE_POSITIVE: (3, "Suppressed"),
    AlertStatus.RESOLVED: (4, "Resolved"),
}


def _ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def to_ocsf(alert: Alert, activity: Activity) -> dict[str, Any]:
    severity_id, severity = _SEVERITY[alert.severity]
    status_id, status = _STATUS[alert.status]
    behavioural = alert.detector != "sigma"
    finding: dict[str, Any] = {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": int(activity),
        "activity_name": activity.name.capitalize(),
        "type_uid": 200400 + int(activity),
        "type_name": f"Detection Finding: {activity.name.capitalize()}",
        "time": _ms(alert.updated_at),
        "severity_id": severity_id,
        "severity": severity,
        "status_id": status_id,
        "status": status,
        "confidence_score": round(alert.score * 100),
        "risk_score": round(alert.score * 100),
        "message": alert.title,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": f"{alert.alert_id}:{alert.version}",
            "correlation_uid": alert.dedup_key,
            "product": {
                "name": "Agent Threat Detection",
                "vendor_name": "kogunlowo123",
                "version": __version__,
            },
        },
        "finding_info": {
            "uid": alert.alert_id,
            "title": alert.title,
            "desc": alert.description,
            "types": [alert.detector],
            "created_time": _ms(alert.created_at),
            "modified_time": _ms(alert.updated_at),
            "first_seen_time": _ms(alert.first_seen),
            "last_seen_time": _ms(alert.last_seen),
            "related_events_count": alert.count,
            "analytic": {
                "uid": alert.rule_id,
                "name": alert.rule_id,
                "type_id": 2 if behavioural else 1,
                "type": "Behavioral" if behavioural else "Rule",
            },
            "attacks": [
                {
                    "version": ATTACK_VERSION,
                    "technique": {"uid": t.uid, "name": t.name},
                    "tactic": {"uid": t.tactic_uid, "name": t.tactic_name},
                }
                for t in alert.techniques
            ],
        },
        "resources": [{"uid": alert.agent_id, "type": "AI Agent", "name": alert.agent_id}],
        "evidences": [
            {"data": {"event_id": e.event_id, "detector": e.detector, **e.evidence}}
            for e in alert.evidence[-5:]
        ],
    }
    if alert.containment_id:
        finding["unmapped"] = {"containment_id": alert.containment_id}
    return finding


def encode(alert: Alert, activity: Activity) -> str:
    return json.dumps(to_ocsf(alert, activity), sort_keys=True, separators=(",", ":"))


class SiemSink(Protocol):
    async def send(self, findings: Sequence[dict[str, Any]]) -> None: ...


class HttpSiemSink:
    """POST findings to an HTTP collector.

    ``ocsf`` sends a JSON array of OCSF objects with a bearer token (Amazon
    Security Lake custom-source collectors, Cribl, Elastic, any HTTP intake).
    ``splunk_hec`` sends HEC event envelopes with ``Authorization: Splunk``.
    """

    def __init__(
        self,
        url: str,
        *,
        token_file: Path | None,
        fmt: str,
        client: httpx.AsyncClient,
    ) -> None:
        if fmt not in {"ocsf", "splunk_hec"}:
            raise ValueError(f"unsupported SIEM format {fmt!r}")
        self._url = url
        self._token_file = token_file
        self._fmt = fmt
        self._client = client

    async def _headers(self) -> dict[str, str]:
        if self._token_file is None:
            return {}
        token = (await asyncio.to_thread(self._token_file.read_text, encoding="utf-8")).strip()
        scheme = "Splunk" if self._fmt == "splunk_hec" else "Bearer"
        return {"Authorization": f"{scheme} {token}"}

    async def send(self, findings: Sequence[dict[str, Any]]) -> None:
        headers = await self._headers()
        if self._fmt == "splunk_hec":
            body = "\n".join(
                json.dumps(
                    {
                        "time": f["time"] / 1000,
                        "sourcetype": "ocsf:detection_finding",
                        "source": "agent-threat-detection",
                        "event": f,
                    },
                    separators=(",", ":"),
                )
                for f in findings
            )
            response = await self._client.post(
                self._url, content=body, headers={**headers, "Content-Type": "application/json"}
            )
        else:
            response = await self._client.post(self._url, json=list(findings), headers=headers)
        response.raise_for_status()


class FileSiemSink:
    """Append findings as JSON Lines, for a log shipper (Fluent Bit, Vector) to forward."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def send(self, findings: Sequence[dict[str, Any]]) -> None:
        lines = "".join(json.dumps(f, separators=(",", ":")) + "\n" for f in findings)
        await asyncio.to_thread(self._write, lines)

    def _write(self, lines: str) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(lines)
            handle.flush()


class SiemDispatcher:
    def __init__(
        self,
        store: ThreatStore,
        sink: SiemSink,
        *,
        now: Callable[[], datetime],
        batch_size: int = 100,
        max_backoff_s: float = 900.0,
        on_result: Callable[[int, int], None] | None = None,
    ) -> None:
        self._store = store
        self._sink = sink
        self._now = now
        self._batch = batch_size
        self._max_backoff = max_backoff_s
        self._on_result = on_result

    async def dispatch_once(self) -> int:
        """Deliver one batch of due findings. Returns the number delivered."""
        due: Sequence[OutboxItem] = await self._store.due_outbox(now=self._now(), limit=self._batch)
        if not due:
            return 0
        try:
            await self._sink.send([json.loads(item.payload) for item in due])
        except Exception as exc:
            attempts = max(item.attempts for item in due) + 1
            delay = min(self._max_backoff, 5.0 * 2 ** (attempts - 1))
            await self._store.mark_failed(due, retry_at=self._now() + timedelta(seconds=delay))
            log.warning("siem_delivery_failed", error=type(exc).__name__, retry_in_s=delay)
            if self._on_result:
                self._on_result(0, len(due))
            return 0
        await self._store.mark_delivered([item.id for item in due], at=self._now())
        if self._on_result:
            self._on_result(len(due), 0)
        return len(due)

    async def run_forever(
        self, interval_s: float, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    ) -> None:
        while True:
            try:
                delivered = await self.dispatch_once()
            except Exception:
                log.exception("siem_dispatch_error")
                delivered = 0
            # Drain quickly while there is a backlog; otherwise poll at the interval.
            await sleep(0 if delivered >= self._batch else interval_s)
