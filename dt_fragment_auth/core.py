"""The checks, independent of any web framework."""
from __future__ import annotations

import asyncio
import hmac
import logging
from dataclasses import dataclass, field

import httpx

from .config import AuthMode, FragmentAuthConfig
from .errors import AuthError, Forbidden, SubjectMismatch, Unauthenticated
from .membership import MembershipChecker
from .verifier import KeyResolver, TokenVerifier

logger = logging.getLogger("dt_fragment_auth")


@dataclass(frozen=True)
class Principal:
    """Who is calling.

    ``kind`` is ``"user"`` (a person, member of this twin), ``"service"``
    (another fragment of the same twin, by the twin's Keycloak client),
    ``"internal"`` (this fragment instance's own component, e.g. its worker)
    or ``"anonymous"`` (no check was applied: mode ``off``, or a failed check
    in mode ``log``).
    """

    kind: str
    subject: str = ""
    username: str = ""
    email: str = ""
    #: Token expiry (unix seconds); None for internal and anonymous callers.
    expires_at: float | None = None
    claims: dict = field(default_factory=dict, repr=False, compare=False)
    #: The raw access token, for a fragment that must forward the caller's
    #: own token to a platform API (e.g. the Simulation API). On a WebSocket
    #: session it is the latest renewed token. Never logged (repr=False).
    token: str = field(default="", repr=False, compare=False)

    @property
    def is_user(self) -> bool:
        return self.kind == "user"

    @property
    def is_internal(self) -> bool:
        return self.kind == "internal"

    @property
    def is_service(self) -> bool:
        return self.kind == "service"


ANONYMOUS = Principal(kind="anonymous")
INTERNAL = Principal(kind="internal", subject="internal")


class FragmentAuth:
    """Entry point. Create one per process::

        auth = FragmentAuth.from_env()
    """

    def __init__(
        self,
        config: FragmentAuthConfig,
        *,
        key_resolver: KeyResolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.config = config
        self._verifier = TokenVerifier(config, key_resolver) if config.mode is not AuthMode.OFF else None
        self.membership = MembershipChecker(config, transport=transport)
        if config.mode is not AuthMode.ENFORCE:
            logger.warning("Fragment authentication mode is %r: callers are NOT refused", config.mode.value)

    @classmethod
    def from_env(cls, **kwargs) -> "FragmentAuth":
        return cls(FragmentAuthConfig.from_env(), **kwargs)

    @property
    def mode(self) -> AuthMode:
        return self.config.mode

    def is_internal_token(self, token: str | None) -> bool:
        expected = self.config.internal_token
        return bool(expected and token) and hmac.compare_digest(token.encode(), expected.encode())

    async def authenticate(self, token: str | None, *, expected_subject: str | None = None) -> Principal:
        """Check a user's access token and twin membership.

        ``expected_subject`` (renewing a session) refuses a token of another
        user before membership is looked at.

        Raises ``AuthError`` on refusal, whatever the mode; callers decide what
        a refusal means (see ``resolve``).
        """
        if not token:
            raise Unauthenticated("Missing token")
        claims = await asyncio.to_thread(self._verifier.verify, token)
        subject = str(claims["sub"])
        if expected_subject is not None and subject != expected_subject:
            raise SubjectMismatch("Token belongs to a different user")
        if self.config.twin_client_id and claims.get("azp") == self.config.twin_client_id:
            # Another fragment of this twin: the twin's own client, which only
            # this twin's fragments hold. No user, so no membership to check.
            return Principal(
                kind="service",
                subject=subject,
                username=self.config.twin_client_id,
                expires_at=float(claims["exp"]),
                claims=claims,
                token=token,
            )
        if not await self.membership.is_member(subject, token):
            raise Forbidden("Not a member of this digital twin")
        return Principal(
            kind="user",
            subject=subject,
            username=str(claims.get("preferred_username") or ""),
            email=str(claims.get("email") or ""),
            expires_at=float(claims["exp"]),
            claims=claims,
            token=token,
        )

    async def resolve(self, *, token: str | None = None, internal_token: str | None = None,
                      allow_internal: bool = True, context: str = "") -> Principal:
        """Apply the mode: the principal, or raise ``AuthError`` (``enforce``),
        or log and return ``ANONYMOUS`` (``log``)."""
        if self.mode is AuthMode.OFF:
            return ANONYMOUS
        try:
            if internal_token is not None:
                if allow_internal and self.is_internal_token(internal_token):
                    return INTERNAL
                raise Unauthenticated("Invalid internal token")
            return await self.authenticate(token)
        except AuthError as e:
            if self.mode is AuthMode.LOG:
                logger.warning("Would refuse %s: %s (mode=log, allowed)", context or "request", e.message)
                return ANONYMOUS
            logger.warning("Refused %s: %s", context or "request", e.message)
            raise

    async def aclose(self) -> None:
        await self.membership.aclose()
