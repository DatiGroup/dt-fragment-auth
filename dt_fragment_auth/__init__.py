"""Authentication and twin-membership checks for fragment APIs.

Every REST and WebSocket caller of a fragment must be either a member of the
fragment's digital twin, proven by the user's own Keycloak access token, or
one of the fragment instance's own components, proven by the instance's
internal token. See README.md.
"""
from .config import AuthMode, ConfigError, FragmentAuthConfig
from .client import TwinTokenClient
from .core import ANONYMOUS, INTERNAL, FragmentAuth, Principal
from .errors import AuthError, Forbidden, MembershipUnavailable, SubjectMismatch, Unauthenticated

__version__ = "0.3.2"

__all__ = [
    "ANONYMOUS",
    "INTERNAL",
    "AuthError",
    "AuthMode",
    "ConfigError",
    "Forbidden",
    "FragmentAuth",
    "FragmentAuthConfig",
    "MembershipUnavailable",
    "Principal",
    "SubjectMismatch",
    "TwinTokenClient",
    "Unauthenticated",
]
