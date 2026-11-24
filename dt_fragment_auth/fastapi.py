"""FastAPI / Starlette integration: a REST dependency and a WebSocket session.

REST::

    from fastapi import Depends
    from dt_fragment_auth import FragmentAuth
    from dt_fragment_auth.fastapi import require_caller

    auth = FragmentAuth.from_env()
    caller = require_caller(auth)

    @app.get("/counter")
    def get_counter(principal = Depends(caller)): ...

WebSocket::

    from dt_fragment_auth.fastapi import accept_websocket

    @app.websocket("/ws/counter")
    async def ws_counter(websocket: WebSocket):
        session = await accept_websocket(auth, websocket)
        if session is None:
            return                      # refused and closed
        try:
            while session.active:
                await session.send_json({...})
                await asyncio.sleep(1)
        finally:
            await session.close()
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any, Awaitable, Callable

from starlette.requests import HTTPConnection, Request
from starlette.websockets import WebSocket, WebSocketDisconnect

from .config import AuthMode
from .core import ANONYMOUS, FragmentAuth, Principal
from .errors import AuthError, SubjectMismatch, Unauthenticated

logger = logging.getLogger("dt_fragment_auth")

#: Header a fragment's own components send their shared internal token in.
INTERNAL_TOKEN_HEADER = "X-Fragment-Token"


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    return value.strip() or None


def require_caller(auth: FragmentAuth, *, allow_internal: bool = True) -> Callable[[Request], Awaitable[Principal]]:
    """A FastAPI dependency that admits a member of the twin (``Authorization:
    Bearer <user token>``) or, when ``allow_internal``, this fragment's own
    components (``X-Fragment-Token: <internal token>``)."""
    from fastapi import HTTPException

    async def dependency(request: Request) -> Principal:
        try:
            return await auth.resolve(
                token=bearer_token(request.headers.get("authorization")),
                internal_token=request.headers.get(INTERNAL_TOKEN_HEADER),
                allow_internal=allow_internal,
                context=f"{request.method} {request.url.path}",
            )
        except AuthError as e:
            headers = {"WWW-Authenticate": "Bearer"} if e.http_status == 401 else None
            raise HTTPException(status_code=e.http_status, detail=e.message, headers=headers) from None

    return dependency


#: Paths a guard leaves open: Kubernetes probes and the engine's health check.
DEFAULT_PUBLIC_PATHS = ("/healthcheck",)


def protect_http(
    auth: FragmentAuth,
    *,
    public_paths: tuple[str, ...] = DEFAULT_PUBLIC_PATHS,
    allow_internal: bool = True,
) -> Callable[[HTTPConnection], Awaitable[Principal | None]]:
    """An app-wide dependency: every HTTP route requires a caller, except
    ``public_paths`` (and anything below them). Deny by default, so a route
    added later cannot be left open by mistake::

        auth = FragmentAuth.from_env()
        app = FastAPI(dependencies=[Depends(protect_http(auth))])

    It applies to routes registered after the app is created, including
    included routers. WebSocket routes are skipped here: their handlers call
    ``accept_websocket``, which runs the first-message protocol.
    """
    caller = require_caller(auth, allow_internal=allow_internal)
    prefixes = tuple(p.rstrip("/") for p in public_paths)

    async def guard(connection: HTTPConnection) -> Principal | None:
        if connection.scope.get("type") != "http":
            return None
        path = connection.url.path.rstrip("/") or "/"
        if any(path == p or path.startswith(p + "/") for p in prefixes):
            return None
        return await caller(connection)  # type: ignore[arg-type]

    return guard


class WebSocketSession:
    """An accepted, authenticated WebSocket.

    Messages from the client are read in the background: ``authenticate``
    messages renew the session's token (a client sends a fresh token before
    the old one expires); anything else is queued for ``receive_json``. When
    the token expires without renewal, the socket is closed with 4401.
    """

    def __init__(self, auth: FragmentAuth, websocket: WebSocket, principal: Principal):
        self._auth = auth
        self.websocket = websocket
        self.principal = principal
        self._active = True
        self._messages: asyncio.Queue[Any] = asyncio.Queue(maxsize=100)
        self._tasks: list[asyncio.Task] = []
        self._expiry_changed = asyncio.Event()

    @property
    def active(self) -> bool:
        return self._active

    def _start(self) -> None:
        self._tasks.append(asyncio.ensure_future(self._read()))
        if self.principal.expires_at is not None:
            self._tasks.append(asyncio.ensure_future(self._expire()))

    async def send_json(self, data: Any) -> bool:
        """Send, or return False if the session is closed."""
        if not self._active:
            return False
        try:
            await self.websocket.send_json(data)
            return True
        except Exception:
            self._active = False
            return False

    async def send_text(self, data: str) -> bool:
        if not self._active:
            return False
        try:
            await self.websocket.send_text(data)
            return True
        except Exception:
            self._active = False
            return False

    async def receive_json(self) -> Any:
        """The client's next non-authentication message. Raises
        ``WebSocketDisconnect`` once the session is closed."""
        item = await self._messages.get()
        if item is _CLOSED:
            raise WebSocketDisconnect(code=1000)
        return item

    async def close(self, code: int = 1000, reason: str = "") -> None:
        was_active = self._active
        self._active = False
        for task in self._tasks:
            if task is not asyncio.current_task():
                task.cancel()
        if was_active:
            with contextlib.suppress(Exception):
                await self.websocket.close(code=code, reason=reason)
        with contextlib.suppress(asyncio.QueueFull):
            self._messages.put_nowait(_CLOSED)

    async def _read(self) -> None:
        try:
            while self._active:
                text = await self.websocket.receive_text()
                message = _parse(text)
                if isinstance(message, dict) and message.get("type") == "authenticate":
                    await self._renew(message.get("token"))
                elif message is not None:
                    with contextlib.suppress(asyncio.QueueFull):
                        self._messages.put_nowait(message)
        except (WebSocketDisconnect, RuntimeError, KeyError):
            # KeyError: a binary frame, which this protocol does not use.
            self._active = False
            with contextlib.suppress(asyncio.QueueFull):
                self._messages.put_nowait(_CLOSED)
        except asyncio.CancelledError:
            raise

    async def _renew(self, token: Any) -> None:
        if self._auth.mode is AuthMode.OFF:
            return
        identified = self.principal.is_user or self.principal.is_service
        expected = self.principal.subject if identified else None
        try:
            principal = await self._auth.authenticate(
                token if isinstance(token, str) else None, expected_subject=expected,
            )
        except SubjectMismatch:
            if self._auth.mode is AuthMode.ENFORCE:
                logger.warning("WebSocket re-authentication as a different user; closing")
                await self.close(code=Unauthenticated.ws_close_code, reason="Different user")
            return
        except AuthError as e:
            if self._auth.mode is AuthMode.LOG or not identified:
                logger.warning("WebSocket re-authentication failed: %s (not enforced)", e.message)
                return
            # A bad refresh does not end a session whose token is still valid;
            # the expiry does, if no good token follows.
            logger.warning("WebSocket re-authentication refused: %s", e.message)
            await self.send_json({"type": "authentication_failed", "reason": e.message})
            return
        self.principal = principal
        self._expiry_changed.set()
        await self.send_json({"type": "authenticated", "expires_at": principal.expires_at})

    async def _expire(self) -> None:
        while self._active and self.principal.expires_at is not None:
            remaining = self.principal.expires_at + self._auth.config.leeway - time.time()
            if remaining <= 0:
                if self._auth.mode is AuthMode.ENFORCE:
                    logger.warning("WebSocket %s: token expired without renewal; closing", self.websocket.url.path)
                    await self.close(code=Unauthenticated.ws_close_code, reason="Token expired")
                return
            self._expiry_changed.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._expiry_changed.wait(), timeout=remaining)


_CLOSED = object()


def _parse(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


async def accept_websocket(auth: FragmentAuth, websocket: WebSocket) -> WebSocketSession | None:
    """Accept the socket and wait for the client's ``{"type": "authenticate",
    "token": "..."}`` message. Nothing is sent before it is valid.

    Returns the session, or None when the client was refused; the socket is
    then already closed (4401 not authenticated, 4403 not a member of the
    twin, 4503 membership could not be checked).
    """
    await websocket.accept()
    path = websocket.url.path

    if auth.mode is AuthMode.OFF:
        session = WebSocketSession(auth, websocket, ANONYMOUS)
        session._start()
        return session

    principal: Principal | None = None
    error: AuthError | None = None
    try:
        text = await asyncio.wait_for(websocket.receive_text(), timeout=auth.config.ws_auth_timeout)
        message = _parse(text)
        if not isinstance(message, dict) or message.get("type") != "authenticate":
            raise Unauthenticated("First message must be {type: authenticate, token}")
        principal = await auth.authenticate(message.get("token") if isinstance(message.get("token"), str) else None)
    except asyncio.TimeoutError:
        error = Unauthenticated("No authenticate message in time")
    except WebSocketDisconnect:
        return None
    except KeyError:
        error = Unauthenticated("First message must be text")
    except AuthError as e:
        error = e

    if error is not None:
        if auth.mode is AuthMode.LOG:
            logger.warning("Would refuse WebSocket %s: %s (mode=log, allowed)", path, error.message)
            principal = ANONYMOUS
        else:
            logger.warning("Refused WebSocket %s: %s", path, error.message)
            with contextlib.suppress(Exception):
                await websocket.close(code=error.ws_close_code, reason=error.message[:120])
            return None

    session = WebSocketSession(auth, websocket, principal)
    if principal.is_user or principal.is_service:
        await session.send_json({"type": "authenticated", "expires_at": principal.expires_at})
    session._start()
    return session
