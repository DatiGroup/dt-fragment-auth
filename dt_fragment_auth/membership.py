"""Is this user a member of the fragment's twin?

The DT API owns twin membership. The fragment asks it with the user's own
token (``GET /digital-twins/accessible-ids``), so the fragment needs no
credentials of its own and the DT API applies exactly the rules it applies
everywhere else. Answers are cached per user for a short time; removing a
user from a twin therefore takes up to ``membership_ttl`` seconds to reach
fragments.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from .config import FragmentAuthConfig
from .errors import MembershipUnavailable

logger = logging.getLogger(__name__)

_MAX_ENTRIES = 10_000


class MembershipChecker:
    def __init__(self, config: FragmentAuthConfig, transport: httpx.AsyncBaseTransport | None = None):
        self._config = config
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        # subject -> (is_member, expires_at monotonic)
        self._cache: dict[str, tuple[bool, float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._config.http_timeout, transport=self._transport)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def forget(self, subject: str | None = None) -> None:
        """Drop cached answers (all, or one user's)."""
        if subject is None:
            self._cache.clear()
        else:
            self._cache.pop(subject, None)

    async def is_member(self, subject: str, token: str) -> bool:
        cached = self._cache.get(subject)
        if cached and cached[1] > time.monotonic():
            return cached[0]

        # One DT API call per user at a time; concurrent requests of the same
        # user (a dashboard opening several sockets) wait for its answer.
        lock = self._locks.setdefault(subject, asyncio.Lock())
        async with lock:
            cached = self._cache.get(subject)
            if cached and cached[1] > time.monotonic():
                return cached[0]
            member = await self._ask(token)
            ttl = self._config.membership_ttl if member else self._config.membership_negative_ttl
            if len(self._cache) >= _MAX_ENTRIES:
                self._prune()
            self._cache[subject] = (member, time.monotonic() + ttl)
        self._locks.pop(subject, None)
        return member

    async def _ask(self, token: str) -> bool:
        url = f"{self._config.dt_api_url}/digital-twins/accessible-ids"
        try:
            response = await self._http().get(url, headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError as e:
            logger.error("Membership check failed, DT API unreachable: %s", e)
            raise MembershipUnavailable("Could not check twin membership") from e
        if response.status_code in (401, 403):
            # The DT API does not accept this user at all (e.g. no platform role).
            return False
        if response.status_code != 200:
            logger.error("Membership check failed, DT API answered %s", response.status_code)
            raise MembershipUnavailable("Could not check twin membership")
        try:
            ids = {str(i).lower() for i in response.json()}
        except ValueError as e:
            raise MembershipUnavailable("Could not check twin membership") from e
        return self._config.digital_twin_id in ids

    def _prune(self) -> None:
        now = time.monotonic()
        for key in [k for k, (_, exp) in self._cache.items() if exp <= now]:
            del self._cache[key]
        if len(self._cache) >= _MAX_ENTRIES:
            self._cache.clear()
