"""Domain errors mapped to HTTP status codes by the API layer."""

from __future__ import annotations


class ThreatDetectionError(Exception):
    code = "invalid_request"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(ThreatDetectionError):
    code = "not_found"
    status = 404


class ConflictError(ThreatDetectionError):
    code = "conflict"
    status = 409


class InvalidStateError(ThreatDetectionError):
    code = "invalid_state"
    status = 409


class UnauthorizedError(ThreatDetectionError):
    code = "unauthorized"
    status = 401


class ForbiddenError(ThreatDetectionError):
    code = "forbidden"
    status = 403


class ApprovalRequiredError(ThreatDetectionError):
    """The policy decision point requires a human to approve this action first."""

    code = "approval_required"
    status = 403


class UnsupportedMediaError(ThreatDetectionError):
    code = "unsupported_media_type"
    status = 415


class DependencyUnavailableError(ThreatDetectionError):
    """A downstream system (identity fabric, IdP, SIEM) could not be reached."""

    code = "temporarily_unavailable"
    status = 503


class RuleValidationError(ThreatDetectionError):
    code = "invalid_rule"
    status = 400
