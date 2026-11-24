"""Offline verification of Keycloak access tokens.

The signature is checked against the realm's public keys (JWKS), which are
fetched once and cached; Keycloak is not called per request. A token signed
with a key that is not in the cache triggers one refetch, so key rotation
works without a restart.
"""
from __future__ import annotations

from typing import Callable

import jwt
from jwt import PyJWKClient

from .config import FragmentAuthConfig
from .errors import Unauthenticated

ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "ES256"]
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]

#: Given a raw token, return the key that should have signed it.
KeyResolver = Callable[[str], object]


class TokenVerifier:
    def __init__(self, config: FragmentAuthConfig, key_resolver: KeyResolver | None = None):
        self._config = config
        if key_resolver is None:
            jwks = PyJWKClient(
                config.jwks_url,
                cache_jwk_set=True,
                lifespan=300,
                timeout=int(config.http_timeout),
            )
            key_resolver = lambda token: jwks.get_signing_key_from_jwt(token).key  # noqa: E731
        self._key_for = key_resolver

    def verify(self, token: str) -> dict:
        """Return the token's claims, or raise ``Unauthenticated``.

        Blocking (it may fetch the JWKS); call it from a thread in async code.
        """
        if not token:
            raise Unauthenticated("Missing token")
        try:
            key = self._key_for(token)
            audiences = list(self._config.audiences)
            if self._config.twin_client_id:
                audiences.append(self._config.twin_client_id)
            claims = jwt.decode(
                token,
                key,
                algorithms=ALGORITHMS,
                audience=audiences,
                leeway=self._config.leeway,
                options={"require": REQUIRED_CLAIMS, "verify_iss": False},
            )
        except jwt.ExpiredSignatureError as e:
            raise Unauthenticated("Token expired") from e
        except jwt.InvalidAudienceError as e:
            raise Unauthenticated("Token is not meant for this platform (audience)") from e
        except jwt.PyJWKClientError as e:
            raise Unauthenticated(f"Token signing key not found: {e}") from e
        except jwt.PyJWTError as e:
            raise Unauthenticated(f"Invalid token: {e}") from e

        # Checked here rather than by PyJWT so several issuers can be accepted
        # (e.g. the same realm reached under two hostnames) on every PyJWT 2.x.
        if str(claims.get("iss", "")).rstrip("/") not in self._config.issuers:
            raise Unauthenticated("Token was issued by an unknown issuer")
        if claims.get("typ") not in (None, "Bearer"):
            # Keycloak marks access tokens "Bearer"; ID and refresh tokens are
            # signed by the same keys and must not be accepted in their place.
            raise Unauthenticated("Not an access token")
        azp = str(claims.get("azp") or "")
        if azp.startswith("dt-") and azp != self._config.twin_client_id:
            # Another twin's client: never admitted, whatever its audience.
            raise Unauthenticated("Token belongs to another digital twin")
        return claims
