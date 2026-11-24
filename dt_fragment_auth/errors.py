"""Why a caller was refused.

Each error maps to one HTTP status and one WebSocket close code, so REST and
WebSocket clients learn the same thing about a refusal.
"""
from __future__ import annotations


class AuthError(Exception):
    http_status = 401
    #: WebSocket close codes 4000-4999 are free for applications; these mirror
    #: the HTTP status (4401 = 401).
    ws_close_code = 4401

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class Unauthenticated(AuthError):
    """No credentials, or credentials that are not valid (bad signature,
    expired, wrong issuer or audience)."""

    http_status = 401
    ws_close_code = 4401


class SubjectMismatch(Unauthenticated):
    """A renewed token belongs to a different user than the session's."""


class Forbidden(AuthError):
    """A valid user who is not a member of this fragment's twin."""

    http_status = 403
    ws_close_code = 4403


class MembershipUnavailable(AuthError):
    """The DT API could not say whether the user is a member. The caller is
    refused (fail closed) but may retry."""

    http_status = 503
    ws_close_code = 4503
