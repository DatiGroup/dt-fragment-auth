import asyncio
import json
import time

import httpx

from dt_fragment_auth import TwinTokenClient


class FakeKeycloak:
    def __init__(self, expires_in=300):
        self.calls = 0
        self.expires_in = expires_in

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        form = dict(x.split("=") for x in request.content.decode().split("&"))
        assert form == {"grant_type": "client_credentials", "client_id": "dt-1", "client_secret": "s"}
        return httpx.Response(200, json={"access_token": f"tok-{self.calls}", "expires_in": self.expires_in})


def make(kc):
    return TwinTokenClient("dt-1", "s", "http://kc/token",
                           transport=httpx.MockTransport(kc.handler),
                           async_transport=httpx.MockTransport(kc.handler))


def test_sync_token_is_cached():
    kc = FakeKeycloak()
    client = make(kc)
    assert client.headers() == {"Authorization": "Bearer tok-1"}
    assert client.headers() == {"Authorization": "Bearer tok-1"}
    assert kc.calls == 1


def test_token_renewed_near_expiry():
    kc = FakeKeycloak(expires_in=30)   # inside the 60 s renewal window
    client = make(kc)
    client.token(); client.token()
    assert kc.calls == 2


def test_async_and_ws_message():
    kc = FakeKeycloak()
    client = make(kc)

    async def go():
        assert await client.aheaders() == {"Authorization": "Bearer tok-1"}
        return json.loads(await client.authenticate_message())
    assert asyncio.run(go()) == {"type": "authenticate", "token": "tok-1"}


def test_keep_authenticated_sends_a_new_token_before_expiry():
    kc = FakeKeycloak(expires_in=64)   # renew 60 s before -> after ~4-5 s
    client = make(kc)
    sent = []

    async def go():
        await client.atoken()
        async def send(message):
            sent.append(json.loads(message))
        task = asyncio.create_task(client.keep_authenticated(send))
        await asyncio.sleep(5.5)
        task.cancel()
    asyncio.run(go())
    assert sent and sent[0]["token"] == "tok-2"


def test_unconfigured_client_sends_no_token():
    client = TwinTokenClient("", "", "")
    assert not client.configured
    assert client.headers() == {}


def test_from_env_needs_only_its_own_settings(monkeypatch):
    for k in ("FRAGMENT_AUTH_JWKS_URL", "FRAGMENT_AUTH_ISSUER", "FRAGMENT_AUTH_MODE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FRAGMENT_AUTH_TWIN_CLIENT_ID", "dt-1")
    monkeypatch.setenv("FRAGMENT_TWIN_CLIENT_SECRET", "s")
    monkeypatch.setenv("FRAGMENT_AUTH_TOKEN_URL", "http://kc/token")
    client = TwinTokenClient.from_env()
    assert client.configured and client.client_id == "dt-1"
