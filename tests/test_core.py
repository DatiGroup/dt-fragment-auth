import asyncio

import pytest

from dt_fragment_auth import (
    ANONYMOUS, INTERNAL, AuthMode, ConfigError, Forbidden, FragmentAuthConfig,
    MembershipUnavailable, Unauthenticated,
)
from conftest import AUDIENCE, INTERNAL as INTERNAL_TOKEN, TWIN, bad_signature_token, make_auth, make_token


def run(coro):
    return asyncio.run(coro)


def test_member_is_admitted_with_identity():
    auth, _ = make_auth()
    principal = run(auth.authenticate(make_token("user-a")))
    assert principal.is_user and principal.subject == "user-a"
    assert principal.email == "user-a@example.com" and principal.expires_at


@pytest.mark.parametrize("token,reason", [
    (None, "Missing"),
    ("not-a-jwt", "Invalid"),
    (make_token(ttl=-60), "expired"),
    (bad_signature_token(), "Invalid"),
    (make_token(iss="http://evil/realms/portal"), "issuer"),
    (make_token(aud="other-client"), "audience"),
    (make_token(typ="Refresh"), "access token"),
])
def test_invalid_tokens_are_unauthenticated(token, reason):
    auth, _ = make_auth()
    with pytest.raises(Unauthenticated, match=reason):
        run(auth.authenticate(token))


def test_member_of_another_twin_is_forbidden():
    auth, _ = make_auth()
    with pytest.raises(Forbidden):
        run(auth.authenticate(make_token("user-b")))


def test_membership_is_cached_per_user():
    auth, dt_api = make_auth()

    async def twice():
        await auth.authenticate(make_token("user-a"))
        await auth.authenticate(make_token("user-a"))
    run(twice())
    assert dt_api.calls == 1


def test_dt_api_failure_fails_closed():
    auth, dt_api = make_auth()
    dt_api.fail = True
    with pytest.raises(MembershipUnavailable):
        run(auth.authenticate(make_token("user-a")))


def test_internal_token():
    auth, _ = make_auth()
    assert run(auth.resolve(internal_token=INTERNAL_TOKEN)) is INTERNAL
    with pytest.raises(Unauthenticated):
        run(auth.resolve(internal_token="wrong"))
    with pytest.raises(Unauthenticated):
        run(auth.resolve(internal_token=INTERNAL_TOKEN, allow_internal=False))


def test_internal_token_disabled_when_not_configured():
    auth, _ = make_auth(internal_token="")
    assert not auth.is_internal_token("")
    assert not auth.is_internal_token("anything")


def test_log_mode_admits_but_does_not_identify():
    auth, _ = make_auth(mode=AuthMode.LOG)
    assert run(auth.resolve(token=None)) is ANONYMOUS
    assert run(auth.resolve(token=make_token("user-a"))).is_user


def test_off_mode_skips_everything():
    auth, dt_api = make_auth(mode=AuthMode.OFF)
    assert run(auth.resolve(token=None)) is ANONYMOUS
    assert dt_api.calls == 0


def test_config_from_env_requires_everything_when_enforcing():
    with pytest.raises(ConfigError, match="FRAGMENT_AUTH_JWKS_URL"):
        FragmentAuthConfig.from_env({})


def test_config_from_env():
    config = FragmentAuthConfig.from_env({
        "FRAGMENT_AUTH_MODE": "log",
        "FRAGMENT_AUTH_JWKS_URL": "http://keycloak:8080/realms/portal/protocol/openid-connect/certs",
        "FRAGMENT_AUTH_ISSUER": "http://localhost:8089/realms/portal/, https://auth.example/realms/portal",
        "FRAGMENT_AUTH_AUDIENCE": AUDIENCE,
        "DIGITAL_TWIN_ID": TWIN.upper(),
        "FRAGMENT_AUTH_DT_API_URL": "http://digitaltwin-api:8080/digital-twin-api/",
        "FRAGMENT_INTERNAL_TOKEN": "s3cr3t-internal",
    })
    assert config.mode is AuthMode.LOG
    assert config.issuers == ("http://localhost:8089/realms/portal", "https://auth.example/realms/portal")
    assert config.digital_twin_id == TWIN
    assert config.dt_api_url.endswith("/digital-twin-api")
    assert "s3cr3t-internal" not in repr(config)


def test_unknown_mode_is_rejected():
    with pytest.raises(ConfigError):
        FragmentAuthConfig.from_env({"FRAGMENT_AUTH_MODE": "maybe"})


def test_off_mode_needs_no_settings():
    assert FragmentAuthConfig.from_env({"FRAGMENT_AUTH_MODE": "off"}).mode is AuthMode.OFF


# --- the twin's own Keycloak client (fragment -> fragment) ------------------

from conftest import OTHER_TWIN_CLIENT, TWIN_CLIENT, service_token  # noqa: E402


def test_twin_client_token_is_a_service_without_membership_check():
    auth, dt_api = make_auth()
    principal = run(auth.authenticate(service_token()))
    assert principal.is_service and principal.username == TWIN_CLIENT
    assert dt_api.calls == 0


def test_other_twins_client_is_refused_even_with_our_audience():
    auth, _ = make_auth()
    # Its audience is its own client, so the audience check refuses it.
    with pytest.raises(Unauthenticated):
        run(auth.authenticate(service_token(OTHER_TWIN_CLIENT)))
    forged = make_token(sub="x", aud=TWIN_CLIENT, azp=OTHER_TWIN_CLIENT)
    with pytest.raises(Unauthenticated, match="another digital twin"):
        run(auth.authenticate(forged))


def test_service_tokens_refused_when_no_twin_client_configured():
    auth, _ = make_auth(twin_client_id="")
    with pytest.raises(Unauthenticated):
        run(auth.authenticate(service_token()))


def test_user_tokens_still_need_membership_with_twin_client_configured():
    auth, _ = make_auth()
    with pytest.raises(Forbidden):
        run(auth.authenticate(make_token("user-b")))


def test_twin_client_id_must_be_a_dt_client():
    with pytest.raises(ConfigError):
        FragmentAuthConfig(mode=AuthMode.ENFORCE, twin_client_id="portal-web").validate()
