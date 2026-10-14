"""Ports the application layer depends on. Adapters live in infrastructure."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class AgentStatusView(Protocol):
    @property
    def status(self) -> str: ...


class AgentLifecycle(Protocol):
    """Suspends and reinstates agents; implemented by the identity fabric client."""

    async def suspend(self, agent_uri: str, *, reason: str) -> AgentStatusView: ...

    async def reinstate(self, agent_uri: str, *, reason: str) -> AgentStatusView: ...
