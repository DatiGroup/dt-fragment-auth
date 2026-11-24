import time
import uuid

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from dt_fragment_auth import AuthMode, FragmentAuth, FragmentAuthConfig

TWIN = "11111111-2222-3333-4444-555555555555"
OTHER_TWIN = "99999999-2222-3333-4444-555555555555"
ISSUER = "http://localhost:8089/realms/portal"
AUDIENCE = "portal-api"
INTERNAL = "internal-secret-value"
TWIN_CLIENT = "dt-11111111"
OTHER_TWIN_CLIENT = "dt-99999999"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_token(sub="user-a", *, ttl=300, iss=ISSUER, aud=AUDIENCE, key=_KEY, typ="Bearer", **extra):
    now = int(time.time())
    claims = {
        "sub": sub, "iss": iss, "aud": aud, "iat": now, "exp": now + ttl, "typ": typ,
        "preferred_username": sub, "email": f"{sub}@example.com", "jti": str(uuid.uuid4()), **extra,
    }
    return jwt.encode(claims, key, algorithm="RS256")


def service_token(client=None, **kw):
    """A client-credentials token of a twin's Keycloak client: azp and aud are
    the client itself (the platform adds the audience mapper)."""
    client = client or TWIN_CLIENT
    return make_token(sub=f"service-account-{client}", aud=client, azp=client, **kw)


def bad_signature_token(**kw):
    return make_token(key=_OTHER_KEY, **kw)


class FakeDtApi:
    """The DT API's /digital-twins/accessible-ids, keyed by token subject."""

    def __init__(self):
        self.members = {"user-a": [TWIN], "user-b": [OTHER_TWIN]}
        self.calls = 0
        self.fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        assert request.url.path.endswith("/digital-twins/accessible-ids")
        if self.fail:
            return httpx.Response(500)
        token = request.headers["authorization"].split(" ", 1)[1]
        sub = jwt.decode(token, options={"verify_signature": False})["sub"]
        return httpx.Response(200, json=self.members.get(sub, []))


def make_auth(mode=AuthMode.ENFORCE, dt_api=None, **overrides):
    config = FragmentAuthConfig(
        mode=mode,
        jwks_url="http://keycloak/certs",
        issuers=(ISSUER,),
        audiences=(AUDIENCE,),
        digital_twin_id=TWIN,
        dt_api_url="http://dt-api/digital-twin-api",
        **{"internal_token": INTERNAL, "twin_client_id": TWIN_CLIENT, **overrides},
    )
    dt_api = dt_api or FakeDtApi()
    auth = FragmentAuth(
        config,
        key_resolver=lambda token: _KEY.public_key(),
        transport=httpx.MockTransport(dt_api.handler),
    )
    return auth, dt_api


@pytest.fixture
def dt_api():
    return FakeDtApi()
