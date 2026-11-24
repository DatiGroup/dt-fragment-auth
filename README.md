# dt-fragment-auth

Authentication and twin-membership checks for the REST and WebSocket APIs of
DigiTDevOps fragments.

A fragment API built with this library answers only:

- **members of its own digital twin**, proven by the user's own Keycloak
  access token, which the widget sends; and
- **its own components** (e.g. its worker calling its API), proven by the
  instance's internal token, which the platform generates per fragment
  instance.

- **other fragments of the same twin**, proven by a token of the twin's own
  Keycloak client (`dt-<short twin id>`), which the platform creates per twin.

Everyone else is refused: anonymous callers, users of other twins, other
twins' fragments, and calls from outside the platform.

This is a standalone library for fragment developers, including external
teams. It does not depend on internal platform SDKs.

## Install

Install it from the git repository; pin a tag:

```text
dt-fragment-auth @ git+https://github.com/DatiGroup/dt-fragment-auth.git@v0.3.2
```

It needs Python 3.10+ and, for the FastAPI helpers, FastAPI 0.100+. The
Dockerfile needs `git` to install it.

## Use

```python
import asyncio
from fastapi import Depends, FastAPI, WebSocket
from dt_fragment_auth import FragmentAuth
from dt_fragment_auth.fastapi import accept_websocket, protect_http

auth = FragmentAuth.from_env()     # fails at startup if misconfigured
# Every HTTP route requires a caller, except /healthcheck and below it.
app = FastAPI(dependencies=[Depends(protect_http(auth))])

@app.get("/healthcheck")
def healthcheck():
    return {"status": "ok"}

@app.get("/counter")               # protected by the guard
def get_counter():
    ...

@app.websocket("/ws/counter")
async def ws_counter(websocket: WebSocket):
    session = await accept_websocket(auth, websocket)
    if session is None:
        return                     # refused; already closed
    try:
        while session.active:
            await session.send_json({"value": 42})
            await asyncio.sleep(1)
    finally:
        await session.close()
```

- **The guard denies by default.** A route added later is protected without
  anyone remembering to. It covers routes registered after the app is
  created, including included routers. Pass
  `protect_http(auth, public_paths=(...))` to open more paths.
- **WebSocket handlers must use `accept_websocket`.** Use the session's
  `send_json` and `receive_json`, not the raw socket. The session reads client
  messages in the background to handle token renewal.
- **To know who is calling** in a route, add `Depends(require_caller(auth))`
  to it. `kind` is `user`, `service`, `internal` or `anonymous`. Users also
  carry `subject`, `username`, `email`, `expires_at` and `claims`.
- **To forward the caller's own token** to a platform API, use
  `principal.token` (REST) or `session.principal.token` (WebSocket; the latest
  renewed token). It is never logged.
  `require_caller(auth, allow_internal=False)` refuses the internal token.

## Calling another fragment of the same twin

A fragment that consumes another fragment's API sends a token of its twin's
client. `TwinTokenClient` gets it (client credentials), caches it and renews it
60 s before it expires:

```python
from dt_fragment_auth import TwinTokenClient

twin = TwinTokenClient.from_env()

requests.get(upstream_url, headers=twin.headers())                 # sync
await http.get(upstream_url, headers=await twin.aheaders())         # async

async with websockets.connect(upstream_ws) as ws:                   # WebSocket
    await ws.send(await twin.authenticate_message())
    renew = asyncio.create_task(twin.keep_authenticated(ws.send))
    try:
        async for message in ws:
            ...
    finally:
        renew.cancel()
```

Without platform settings (a local run) it is not `configured` and sends no
token. The called fragment sees `principal.kind == "service"`.

## The protocol

### REST

```http
Authorization: Bearer <user access token>      # a person, from a widget
X-Fragment-Token: <internal token>             # this fragment's own components
```

| Status | Meaning |
|---|---|
| 401 + `WWW-Authenticate: Bearer` | missing, invalid or expired token |
| 403 | valid user, not a member of this twin |
| 503 | membership could not be checked (DT API unavailable); retry |

### WebSocket

Browsers cannot set headers on a WebSocket, so the token travels as the first
message:

1. The client connects and sends `{"type": "authenticate", "token": "<access token>"}`.
2. The fragment sends **nothing** until that token is valid and the user is a
   member. It then sends `{"type": "authenticated", "expires_at": <unix seconds>}`
   and starts streaming.
3. Before `expires_at`, the client sends another `authenticate` with its
   refreshed token on the same socket. The fragment answers with a new
   `authenticated`, and the stream continues without a gap. A refresh the
   fragment rejects is answered with `{"type": "authentication_failed",
   "reason": ...}`, and the session keeps running until its current token
   expires.
4. If the token expires without a valid renewal, the fragment closes the
   socket.

The fragment closes the socket with these codes:

| Code | Meaning | Client should |
|---|---|---|
| 4401 | no/invalid/expired token, nothing sent within 10 s, or a renewal as a different user | reconnect with a fresh token |
| 4403 | not a member of this twin | not retry (or rarely) |
| 4503 | membership could not be checked | retry with backoff |

Other client messages, which are not `authenticate`, are available through
`await session.receive_json()`.

## What is checked

- **Signature**, against the realm's public keys (JWKS). The keys are fetched
  once and cached. A token signed with an unknown key triggers one refetch,
  so Keycloak key rotation needs no restart. Keycloak is not called per
  request.
- **`exp`/`iat`** with 10 s leeway, **`iss`** against
  `FRAGMENT_AUTH_ISSUER`, **`aud`** against `FRAGMENT_AUTH_AUDIENCE`, and
  `typ` is `Bearer`, so ID and refresh tokens are refused.
- **Twin membership**: the DT API's `GET /digital-twins/accessible-ids`,
  called with the user's own token, must list this fragment's
  `DIGITAL_TWIN_ID`. The fragment needs no credentials for this, and the DT
  API decides membership the same way it does everywhere else.
  - Answers are cached per user: 60 s for members, 15 s for non-members.
  - Removing a user from a twin therefore takes up to a minute to reach
    fragments; open sockets close when their token is next renewed.
  - If the DT API is unavailable, callers are refused (fail closed).
- **Internal token**: compared in constant time; empty means no internal
  callers.
- **Same-twin fragments**: a token whose `azp` is `FRAGMENT_AUTH_TWIN_CLIENT_ID`
  (audience = that client) is a `service` caller; no membership check. A token
  of any other `dt-*` client is refused.

## Configuration

The platform sets these when it deploys the fragment. A fragment wires them
into its containers through its k8s manifest:

```yaml
env:
  - { name: FRAGMENT_AUTH_MODE,       value: "${FRAGMENT_AUTH_MODE}" }
  - { name: FRAGMENT_AUTH_JWKS_URL,   value: "${FRAGMENT_AUTH_JWKS_URL}" }
  - { name: FRAGMENT_AUTH_ISSUER,     value: "${FRAGMENT_AUTH_ISSUER}" }
  - { name: FRAGMENT_AUTH_AUDIENCE,   value: "${FRAGMENT_AUTH_AUDIENCE}" }
  - { name: FRAGMENT_AUTH_DT_API_URL, value: "${FRAGMENT_AUTH_DT_API_URL}" }
  - { name: DIGITAL_TWIN_ID,          value: "${DIGITAL_TWIN_ID}" }
  - { name: FRAGMENT_AUTH_TWIN_CLIENT_ID, value: "${FRAGMENT_AUTH_TWIN_CLIENT_ID}" }
  - name: FRAGMENT_INTERNAL_TOKEN
    valueFrom:
      secretKeyRef: { name: "${FRAGMENT_AUTH_SECRET}", key: FRAGMENT_INTERNAL_TOKEN }
  # Only in containers that call other fragments:
  - { name: FRAGMENT_AUTH_TOKEN_URL, value: "${FRAGMENT_AUTH_TOKEN_URL}" }
  - name: FRAGMENT_TWIN_CLIENT_SECRET
    valueFrom:
      secretKeyRef: { name: "${FRAGMENT_TWIN_AUTH_SECRET}", key: FRAGMENT_TWIN_CLIENT_SECRET, optional: true }
```

| Variable | Meaning |
|---|---|
| `FRAGMENT_AUTH_MODE` | `enforce` (default), `log` (check and log, refuse nothing — for rollout) or `off` |
| `FRAGMENT_AUTH_JWKS_URL` | realm certs URL, reachable from the pod |
| `FRAGMENT_AUTH_ISSUER` | accepted `iss`, comma-separated; the URL the browser logs in at |
| `FRAGMENT_AUTH_AUDIENCE` | accepted `aud`, comma-separated |
| `FRAGMENT_AUTH_DT_API_URL` | DT API base URL |
| `DIGITAL_TWIN_ID` | the twin this instance belongs to |
| `FRAGMENT_INTERNAL_TOKEN` | this instance's internal token (from its Secret) |
| `FRAGMENT_AUTH_TWIN_CLIENT_ID` | the twin's client, `dt-<short id>`: accepted `azp`/`aud` of calls from same-twin fragments |
| `FRAGMENT_AUTH_TOKEN_URL` | token endpoint for this fragment's own calls to other fragments |
| `FRAGMENT_TWIN_CLIENT_SECRET` | the twin client's secret (from its Secret), only for fragments that call others |
| `FRAGMENT_AUTH_MEMBERSHIP_TTL` / `_NEGATIVE_TTL` | membership cache, seconds (60 / 15) |
| `FRAGMENT_AUTH_WS_TIMEOUT` | seconds to wait for the first `authenticate` (10) |

In `enforce` or `log` mode the fragment refuses to start if a required
variable is missing, rather than silently admitting everyone. For a local
run outside the platform, set them or use `FRAGMENT_AUTH_MODE=off`.

## Logging

Refusals and closes are logged at WARNING on the `dt_fragment_auth` logger,
with the reason and never the token (e.g. `Refused GET /counter: Not a member
of this digital twin`, `WebSocket /ws/counter: token expired without renewal;
closing`), so they show in the fragment's logs without extra configuration.

## Develop

```bash
pip install -e .[dev]
pytest
```

The tests sign tokens with a generated key and fake the DT API, so they need
no network.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
