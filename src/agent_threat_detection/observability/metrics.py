"""Service metrics exposed on /metrics in Prometheus text format."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class ThreatMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "atd_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        )
        self.events = Counter(
            "atd_events_ingested_total",
            "Telemetry events accepted for detection",
            ["source"],
            registry=self.registry,
        )
        self.duplicates = Counter(
            "atd_events_duplicate_total",
            "Telemetry events skipped because they were already processed",
            ["source"],
            registry=self.registry,
        )
        self.rejected = Counter(
            "atd_events_rejected_total",
            "Telemetry records that could not be normalized",
            ["source"],
            registry=self.registry,
        )
        self.signals = Counter(
            "atd_signals_total",
            "Detector signals raised (before deduplication)",
            ["source"],
            registry=self.registry,
        )
        self.alerts = Counter(
            "atd_alerts_total",
            "Alerts opened or updated",
            ["activity"],
            registry=self.registry,
        )
        self.open_alerts = Gauge(
            "atd_open_alerts",
            "Open alerts by severity",
            ["severity"],
            registry=self.registry,
        )
        self.containment = Counter(
            "atd_containment_actions_total",
            "Containment actions by resulting status",
            ["status"],
            registry=self.registry,
        )
        self.siem_delivered = Counter(
            "atd_siem_findings_delivered_total",
            "Findings delivered to the SIEM",
            registry=self.registry,
        )
        self.siem_failed = Counter(
            "atd_siem_delivery_failures_total",
            "Findings whose delivery attempt failed (retried with back-off)",
            registry=self.registry,
        )
        self.siem_backlog = Gauge(
            "atd_siem_outbox_backlog", "Findings waiting for SIEM delivery", registry=self.registry
        )
        self.authorization = Counter(
            "atd_inbound_authorization_total",
            "Inbound agent authorization outcomes",
            ["channel", "outcome"],
            registry=self.registry,
        )
        self.ingest_latency = Histogram(
            "atd_ingest_batch_duration_seconds",
            "Time to process one telemetry batch end to end",
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        )

    def siem_result(self, delivered: int, failed: int) -> None:
        if delivered:
            self.siem_delivered.inc(delivered)
        if failed:
            self.siem_failed.inc(failed)
