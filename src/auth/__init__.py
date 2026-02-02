"""
Resurface Authentication Engine — handles auth flows for vulnerability replay
"""
from src.auth.auth_config import AuthProfile, AuthType, AuthConfig
from src.auth.auth_manager import AuthManager, AuthSession

try:
    from src.auth.auto_auth import AutoAuth, AutoAuthResult, CachedCredentials, CredentialCache
    HAS_AUTO_AUTH = True
except ImportError:
    HAS_AUTO_AUTH = False

__all__ = [
    'AuthProfile', 'AuthType', 'AuthConfig', 'AuthManager', 'AuthSession',
    'AutoAuth', 'AutoAuthResult', 'CachedCredentials', 'CredentialCache',
    'HAS_AUTO_AUTH',
]
