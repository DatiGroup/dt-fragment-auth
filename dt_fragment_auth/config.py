"""Configuration, read from the environment the platform gives a fragment.

The orchestrator injects these into every fragment it deploys (through the
fragment's own k8s manifest, as ``${VAR}`` placeholders). A fragment does
not configure them by hand.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum


class AuthMode(str, Enum):
    """How strictly a fragment applies the checks.

    ``enforce`` rejects every request without a valid token from a member of
    the twin. ``log`` runs the same checks but only logs failures, for rolling
    the checks out without breaking callers. ``off`` skips them.
    """

    OFF = "off"
    LOG = "log"
    ENFORCE = "enforce"


class ConfigError(ValueError):
    """The configuration cannot support the requested mode."""


def _split(value: str | None) -> tuple[str, ...]:
    return tuple(v.strip().rstrip("/") for v in (value or "").split(",") if v.strip())


@dataclass(frozen=True)
class FragmentAuthConfig:
    mode: AuthMode = AuthMode.ENFORCE
    #: Where to fetch the realm's signing keys (an in-cluster URL).
    jwks_url: str = ""
    #: Accepted token issuers. The issuer is the URL the *browser* used to log
    #: in, which usually differs from the in-cluster ``jwks_url`` host.
    issuers: tuple[str, ...] = ()
    #: Accepted audiences; the token's ``aud`` must contain one of them.
    audiences: tuple[str, ...] = ()
    #: The twin this fragment instance belongs to.
    digital_twin_id: str = ""
    #: DT API base URL, used to ask whether a user is a member of the twin.
    dt_api_url: str = ""
    #: Shared secret of this fragment instance's own components (e.g. its
    #: worker calling its API). Empty disables internal callers.
    internal_token: str = field(default="", repr=False)
    #: The twin's Keycloak client (``dt-<short twin id>``). Tokens this client
    #: obtained (``azp``) are accepted as other fragments of the same twin;
    #: they carry it as audience too. Empty disables service callers.
    twin_client_id: str = ""
    #: Its secret, for this fragment's own calls to other fragments (see
    #: ``TwinTokenClient``). Not needed to accept calls.
    twin_client_secret: str = field(default="", repr=False)
    #: Token endpoint for those calls (an in-cluster URL).
    token_url: str = ""
    #: How long a membership answer is reused, in seconds.
    membership_ttl: float = 60.0
    #: How long a "not a member" answer is reused, in seconds. Shorter, so a
    #: user who was just added gets in quickly.
    membership_negative_ttl: float = 15.0
    #: Seconds a WebSocket client has to send its first ``authenticate``.
    ws_auth_timeout: float = 10.0
    #: Clock skew tolerated when checking ``exp``/``iat``, in seconds.
    leeway: float = 10.0
    #: Timeout of calls to Keycloak and the DT API, in seconds.
    http_timeout: float = 5.0

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "FragmentAuthConfig":
        env = os.environ if environ is None else environ
        raw_mode = (env.get("FRAGMENT_AUTH_MODE") or AuthMode.ENFORCE.value).strip().lower()
        try:
            mode = AuthMode(raw_mode)
        except ValueError as e:
            raise ConfigError(
                f"FRAGMENT_AUTH_MODE={raw_mode!r}; expected one of "
                f"{', '.join(m.value for m in AuthMode)}"
            ) from e

        config = cls(
            mode=mode,
            jwks_url=(env.get("FRAGMENT_AUTH_JWKS_URL") or "").strip(),
            issuers=_split(env.get("FRAGMENT_AUTH_ISSUER")),
            audiences=tuple(a for a in _split(env.get("FRAGMENT_AUTH_AUDIENCE"))),
            digital_twin_id=(env.get("DIGITAL_TWIN_ID") or "").strip().lower(),
            dt_api_url=(env.get("FRAGMENT_AUTH_DT_API_URL") or "").strip().rstrip("/"),
            internal_token=(env.get("FRAGMENT_INTERNAL_TOKEN") or "").strip(),
            twin_client_id=(env.get("FRAGMENT_AUTH_TWIN_CLIENT_ID") or "").strip(),
            twin_client_secret=(env.get("FRAGMENT_TWIN_CLIENT_SECRET") or "").strip(),
            token_url=(env.get("FRAGMENT_AUTH_TOKEN_URL") or "").strip(),
            membership_ttl=float(env.get("FRAGMENT_AUTH_MEMBERSHIP_TTL") or 60),
            membership_negative_ttl=float(env.get("FRAGMENT_AUTH_MEMBERSHIP_NEGATIVE_TTL") or 15),
            ws_auth_timeout=float(env.get("FRAGMENT_AUTH_WS_TIMEOUT") or 10),
        )
        config.validate()
        return config

    def validate(self) -> None:
        """Refuse to start half-configured: a fragment that silently lets
        everyone in because a variable is missing is worse than one that
        does not start."""
        if self.mode is AuthMode.OFF:
            return
        if self.twin_client_id and not self.twin_client_id.startswith("dt-"):
            raise ConfigError("FRAGMENT_AUTH_TWIN_CLIENT_ID must be the twin's dt-<id> client")
        missing = [
            name
            for name, value in (
                ("FRAGMENT_AUTH_JWKS_URL", self.jwks_url),
                ("FRAGMENT_AUTH_ISSUER", self.issuers),
                ("FRAGMENT_AUTH_AUDIENCE", self.audiences),
                ("DIGITAL_TWIN_ID", self.digital_twin_id),
                ("FRAGMENT_AUTH_DT_API_URL", self.dt_api_url),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                f"FRAGMENT_AUTH_MODE={self.mode.value} needs {', '.join(missing)}. "
                "The platform sets these when it deploys the fragment; for a local "
                "run set them, or set FRAGMENT_AUTH_MODE=off."
            )
