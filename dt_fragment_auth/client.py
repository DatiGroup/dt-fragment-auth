"""Calling other fragments of the same twin.

A fragment that consumes another fragment's REST or WebSocket API proves it
belongs to the same digital twin with a token of the twin's Keycloak client
(client credentials). The platform injects the client id, secret and token
endpoint; tokens are cached and renewed shortly before they expire.

REST (sync, e.g. requests)::

    twin = TwinTokenClient.from_env()
    requests.get(url, headers=twin.headers())

REST (async, e.g. httpx)::

    async with httpx.AsyncClient() as http:
        await http.get(url, headers=await twin.aheaders())

WebSocket (the server expects the token as the first message, and a renewed
one before it expires)::

    async with websockets.connect(url) as ws:
        await ws.send(await twin.authenticate_message())
        keepalive = asyncio.create_task(twin.keep_authenticated(ws.send))
        try:
            async for message in ws:
                ...
        finally:
            keepalive.cancel()
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from typing import Awaitable, Callable

import httpx

from .config import FragmentAuthConfig

#: Renew this long before a token expires.
_RENEW_BEFORE = 60.0


class TwinTokenClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_url: str,
        *,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
        async_transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.client_id = client_id
        self._secret = client_secret
        self.token_url = token_url
        self._timeout = timeout
        self._transport = transport
        self._async_transport = async_transport
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()
        self._alock: asyncio.Lock | None = None

    @classmethod
    def from_env(cls, config: FragmentAuthConfig | None = None, **kwargs) -> "TwinTokenClient":
        """Read only the three settings a caller needs, so a worker that only
        calls other fragments needs none of the settings for checking callers."""
        if config is not None:
            return cls(config.twin_client_id, config.twin_client_secret, config.token_url, **kwargs)
        return cls(
            (os.environ.get("FRAGMENT_AUTH_TWIN_CLIENT_ID") or "").strip(),
            (os.environ.get("FRAGMENT_TWIN_CLIENT_SECRET") or "").strip(),
            (os.environ.get("FRAGMENT_AUTH_TOKEN_URL") or "").strip(),
            **kwargs,
        )

    @property
    def configured(self) -> bool:
        """False when the platform gave this fragment no twin client (e.g. a
        local run); calls then go out without a token."""
        return bool(self.client_id and self._secret and self.token_url)

    @property
    def expires_at(self) -> float:
        return self._expires_at

    def _fresh(self) -> bool:
        return self._token is not None and time.time() < self._expires_at - _RENEW_BEFORE

    def _store(self, payload: dict) -> str:
        self._token = payload["access_token"]
        self._expires_at = time.time() + float(payload.get("expires_in", 300))
        return self._token

    def _form(self) -> dict:
        return {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self._secret}

    def token(self) -> str | None:
        """A valid access token (blocking), or None if not configured."""
        if not self.configured:
            return None
        with self._lock:
            if self._fresh():
                return self._token
            with httpx.Client(timeout=self._timeout, transport=self._transport) as http:
                response = http.post(self.token_url, data=self._form())
            response.raise_for_status()
            return self._store(response.json())

    async def atoken(self) -> str | None:
        """A valid access token, or None if not configured."""
        if not self.configured:
            return None
        if self._alock is None:
            self._alock = asyncio.Lock()
        async with self._alock:
            if self._fresh():
                return self._token
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._async_transport) as http:
                response = await http.post(self.token_url, data=self._form())
            response.raise_for_status()
            return self._store(response.json())

    def headers(self) -> dict[str, str]:
        token = self.token()
        return {"Authorization": f"Bearer {token}"} if token else {}

    async def aheaders(self) -> dict[str, str]:
        token = await self.atoken()
        return {"Authorization": f"Bearer {token}"} if token else {}

    async def authenticate_message(self) -> str:
        """The WebSocket ``authenticate`` message with a valid token."""
        return json.dumps({"type": "authenticate", "token": await self.atoken() or ""})

    async def keep_authenticated(self, send: Callable[[str], Awaitable[object]]) -> None:
        """Send a renewed ``authenticate`` on an open socket before each token
        expires. Run as a task; cancel it when the socket closes."""
        if not self.configured:
            return
        while True:
            await asyncio.sleep(max(5.0, self._expires_at - _RENEW_BEFORE - time.time()))
            self._expires_at = 0.0   # force a new token
            await send(await self.authenticate_message())
