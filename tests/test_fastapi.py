import asyncio
import json
import time

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from dt_fragment_auth import AuthMode, Principal
from dt_fragment_auth.fastapi import INTERNAL_TOKEN_HEADER, accept_websocket, require_caller
from conftest import INTERNAL, make_auth, make_token


def build_app(mode=AuthMode.ENFORCE, **overrides):
    auth, dt_api = make_auth(mode=mode, **overrides)
    app = FastAPI()
    caller = require_caller(auth)
    users_only = require_caller(auth, allow_internal=False)

    @app.get("/healthcheck")
    def healthcheck():
        return {"status": "ok"}

    @app.get("/counter")
    def get_counter(principal: Principal = Depends(caller)):
        return {"value": 1, "kind": principal.kind}

    @app.get("/users-only")
    def users(principal: Principal = Depends(users_only)):
        return {"kind": principal.kind}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        session = await accept_websocket(auth, websocket)
        if session is None:
            return
        try:
            while session.active:
                await session.send_json({"value": 1, "kind": session.principal.kind})
                await asyncio.sleep(0.05)
        finally:
            await session.close()

    return TestClient(app), dt_api


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# --- REST -------------------------------------------------------------------

def test_health_stays_open():
    client, _ = build_app()
    assert client.get("/healthcheck").status_code == 200


def test_rest_member():
    client, _ = build_app()
    r = client.get("/counter", headers=bearer(make_token("user-a")))
    assert r.status_code == 200 and r.json()["kind"] == "user"


def test_rest_without_token_is_401_with_challenge():
    client, _ = build_app()
    r = client.get("/counter")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_rest_non_member_is_403():
    client, _ = build_app()
    assert client.get("/counter", headers=bearer(make_token("user-b"))).status_code == 403


def test_rest_wrong_scheme_is_401():
    client, _ = build_app()
    r = client.get("/counter", headers={"Authorization": f"Basic {make_token('user-a')}"})
    assert r.status_code == 401


def test_rest_internal_caller():
    client, _ = build_app()
    r = client.get("/counter", headers={INTERNAL_TOKEN_HEADER: INTERNAL})
    assert r.status_code == 200 and r.json()["kind"] == "internal"
    assert client.get("/counter", headers={INTERNAL_TOKEN_HEADER: "guess"}).status_code == 401
    assert client.get("/users-only", headers={INTERNAL_TOKEN_HEADER: INTERNAL}).status_code == 401


def test_rest_dt_api_down_is_503():
    client, dt_api = build_app()
    dt_api.fail = True
    assert client.get("/counter", headers=bearer(make_token("user-a"))).status_code == 503


def test_rest_log_mode_lets_through():
    client, _ = build_app(mode=AuthMode.LOG)
    r = client.get("/counter")
    assert r.status_code == 200 and r.json()["kind"] == "anonymous"


# --- WebSocket --------------------------------------------------------------

def authenticate(ws, token):
    ws.send_text(json.dumps({"type": "authenticate", "token": token}))


def test_ws_member_gets_ack_then_data():
    client, _ = build_app()
    with client.websocket_connect("/ws") as ws:
        authenticate(ws, make_token("user-a"))
        ack = ws.receive_json()
        assert ack["type"] == "authenticated" and ack["expires_at"] > time.time()
        assert ws.receive_json() == {"value": 1, "kind": "user"}


@pytest.mark.parametrize("first,code", [
    (lambda: json.dumps({"type": "authenticate", "token": make_token("user-b")}), 4403),
    (lambda: json.dumps({"type": "authenticate", "token": "garbage"}), 4401),
    (lambda: json.dumps({"type": "hello"}), 4401),
    (lambda: "not json", 4401),
])
def test_ws_refused_before_any_data(first, code):
    client, _ = build_app()
    with client.websocket_connect("/ws") as ws:
        ws.send_text(first())
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_json()
        assert e.value.code == code


def test_ws_silent_client_is_closed_after_timeout():
    client, _ = build_app(ws_auth_timeout=0.2)
    with client.websocket_connect("/ws") as ws:
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_json()
        assert e.value.code == 4401


def test_ws_expired_token_closes_session():
    client, _ = build_app(leeway=0)
    with client.websocket_connect("/ws") as ws:
        authenticate(ws, make_token("user-a", ttl=1))
        assert ws.receive_json()["type"] == "authenticated"
        with pytest.raises(WebSocketDisconnect) as e:
            while True:
                ws.receive_json()
        assert e.value.code == 4401


def test_ws_renewal_keeps_session_open():
    client, _ = build_app(leeway=0)
    with client.websocket_connect("/ws") as ws:
        authenticate(ws, make_token("user-a", ttl=1))
        assert ws.receive_json()["type"] == "authenticated"
        authenticate(ws, make_token("user-a", ttl=300))
        deadline = time.time() + 2.0
        renewed = False
        while time.time() < deadline:   # past the first token's expiry
            message = ws.receive_json()
            renewed = renewed or message.get("type") == "authenticated"
        assert renewed


def test_ws_renewal_as_another_user_closes():
    client, _ = build_app()
    with client.websocket_connect("/ws") as ws:
        authenticate(ws, make_token("user-a"))
        assert ws.receive_json()["type"] == "authenticated"
        authenticate(ws, make_token("user-c"))
        with pytest.raises(WebSocketDisconnect) as e:
            while True:
                ws.receive_json()
        assert e.value.code == 4401


def test_ws_bad_renewal_is_reported_not_fatal():
    client, _ = build_app()
    with client.websocket_connect("/ws") as ws:
        authenticate(ws, make_token("user-a"))
        assert ws.receive_json()["type"] == "authenticated"
        authenticate(ws, "garbage")
        seen = [ws.receive_json() for _ in range(5)]
        assert any(m.get("type") == "authentication_failed" for m in seen)
        assert seen[-1] == {"value": 1, "kind": "user"}


def test_ws_log_mode_streams_without_token():
    client, _ = build_app(mode=AuthMode.LOG, ws_auth_timeout=0.2)
    with client.websocket_connect("/ws") as ws:
        assert ws.receive_json() == {"value": 1, "kind": "anonymous"}


# --- fragment -> fragment ---------------------------------------------------

from conftest import OTHER_TWIN_CLIENT, service_token  # noqa: E402


def test_rest_same_twin_fragment_is_admitted():
    client, dt_api = build_app()
    r = client.get("/counter", headers=bearer(service_token()))
    assert r.status_code == 200 and r.json()["kind"] == "service"
    assert dt_api.calls == 0


def test_rest_other_twin_fragment_is_refused():
    client, _ = build_app()
    assert client.get("/counter", headers=bearer(service_token(OTHER_TWIN_CLIENT))).status_code == 401


def test_ws_same_twin_fragment_streams_and_renews():
    client, _ = build_app()
    with client.websocket_connect("/ws") as ws:
        authenticate(ws, service_token())
        assert ws.receive_json()["type"] == "authenticated"
        assert ws.receive_json() == {"value": 1, "kind": "service"}
        authenticate(ws, service_token())
        seen = [ws.receive_json() for _ in range(3)]
        assert any(m.get("type") == "authenticated" for m in seen)


# --- app-wide guard ---------------------------------------------------------

from fastapi import APIRouter  # noqa: E402

from dt_fragment_auth.fastapi import protect_http  # noqa: E402


def build_guarded_app(**overrides):
    auth, dt_api = make_auth(**overrides)
    app = FastAPI(dependencies=[Depends(protect_http(auth))])
    router = APIRouter()

    @app.get("/healthcheck")
    def health():
        return {"status": "ok"}

    @app.get("/healthcheck/live")
    def live():
        return {"status": "ok"}

    @app.get("/data")
    def data():
        return {"value": 1}

    @router.get("/from-router")
    def routed():
        return {"value": 2}

    app.include_router(router)

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        session = await accept_websocket(auth, websocket)
        if session is None:
            return
        try:
            await session.send_json({"value": 3})
            while session.active:
                await asyncio.sleep(0.05)
        finally:
            await session.close()

    return TestClient(app)


def test_guard_denies_by_default_and_leaves_health_open():
    client = build_guarded_app()
    assert client.get("/healthcheck").status_code == 200
    assert client.get("/healthcheck/live").status_code == 200
    assert client.get("/data").status_code == 401
    assert client.get("/from-router").status_code == 401
    assert client.get("/data", headers=bearer(make_token("user-a"))).status_code == 200
    assert client.get("/from-router", headers=bearer(service_token())).status_code == 200
    assert client.get("/data", headers={INTERNAL_TOKEN_HEADER: INTERNAL}).status_code == 200
    assert client.get("/data", headers=bearer(make_token("user-b"))).status_code == 403


def test_guard_leaves_websockets_to_accept_websocket():
    client = build_guarded_app()
    with client.websocket_connect("/ws") as ws:
        authenticate(ws, make_token("user-a"))
        assert ws.receive_json()["type"] == "authenticated"
        assert ws.receive_json() == {"value": 3}


def test_principal_carries_the_latest_token_for_forwarding():
    auth, _ = make_auth()
    app = FastAPI()
    seen = []

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        session = await accept_websocket(auth, websocket)
        if session is None:
            return
        try:
            while session.active:
                if session.principal.token not in seen:
                    seen.append(session.principal.token)
                    await session.send_json({"n": len(seen)})
                await asyncio.sleep(0.02)
        finally:
            await session.close()

    first, second = make_token("user-a"), make_token("user-a")
    assert first not in repr(Principal(kind="user", token=first))   # never logged
    with TestClient(app).websocket_connect("/ws") as sock:
        authenticate(sock, first)
        assert sock.receive_json()["type"] == "authenticated"
        assert sock.receive_json() == {"n": 1}
        authenticate(sock, second)
        msgs = [sock.receive_json() for _ in range(2)]
        assert {"n": 2} in msgs
    assert seen == [first, second]
