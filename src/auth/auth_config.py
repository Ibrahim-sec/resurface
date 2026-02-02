"""
Authentication configuration — profile definitions and loading from YAML/env vars.
"""
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AuthType(str, Enum):
    COOKIE = "cookie"
    JWT = "jwt"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    CUSTOM_HEADER = "custom_header"


@dataclass
class AuthProfile:
    """A single authentication profile for a target."""
    name: str
    auth_type: AuthType
    # Domains this profile applies to (matched against target_domain)
    domains: list[str] = field(default_factory=list)

    # --- Cookie-based auth ---
    login_url: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    username: Optional[str] = None
    password: Optional[str] = None
    extra_fields: dict = field(default_factory=dict)  # Additional form fields

    # --- JWT / Bearer token auth ---
    # login_url is reused; body is the JSON payload to POST
    login_body: dict = field(default_factory=dict)
    token_path: str = "token"  # dot-separated path into JSON response

    # --- API key ---
    header: str = "X-API-Key"
    key: Optional[str] = None
    # If key should be in query param instead of header
    param_name: Optional[str] = None

    # --- OAuth2 client-credentials ---
    token_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scope: Optional[str] = None

    # --- Cookie auth: CSRF support ---
    csrf_field: Optional[str] = None       # Hidden form field name holding the CSRF token (e.g. "user_token")
    csrf_pattern: Optional[str] = None     # Regex to extract CSRF token from HTML (auto-built from csrf_field if not set)
    extra_cookies: dict = field(default_factory=dict)  # Additional cookies to inject (e.g. security: low)

    # --- Custom header ---
    custom_headers: dict = field(default_factory=dict)

    def resolve_env_vars(self) -> None:
        """Replace ${ENV_VAR} placeholders with actual env var values."""
        for attr in (
            'username', 'password', 'key', 'client_id', 'client_secret',
            'login_url', 'token_url', 'scope',
        ):
            val = getattr(self, attr, None)
            if isinstance(val, str) and val.startswith('${') and val.endswith('}'):
                env_name = val[2:-1]
                resolved = os.environ.get(env_name, '')
                setattr(self, attr, resolved)

        # Resolve inside login_body values
        resolved_body = {}
        for k, v in self.login_body.items():
            if isinstance(v, str) and v.startswith('${') and v.endswith('}'):
                resolved_body[k] = os.environ.get(v[2:-1], '')
            else:
                resolved_body[k] = v
        self.login_body = resolved_body

        # Resolve inside custom_headers values
        resolved_headers = {}
        for k, v in self.custom_headers.items():
            if isinstance(v, str) and v.startswith('${') and v.endswith('}'):
                resolved_headers[k] = os.environ.get(v[2:-1], '')
            else:
                resolved_headers[k] = v
        self.custom_headers = resolved_headers

        # Resolve inside extra_fields
        resolved_extra = {}
        for k, v in self.extra_fields.items():
            if isinstance(v, str) and v.startswith('${') and v.endswith('}'):
                resolved_extra[k] = os.environ.get(v[2:-1], '')
            else:
                resolved_extra[k] = v
        self.extra_fields = resolved_extra


@dataclass
class AuthConfig:
    """Top-level auth configuration holding all profiles."""
    profiles: dict[str, AuthProfile] = field(default_factory=dict)

    def get_profile_for_domain(self, domain: str) -> Optional[AuthProfile]:
        """Find the best auth profile whose domains list matches the given domain.
        
        Matching priority:
        1. Exact match
        2. Target domain ends with .{pattern} (subdomain match)
        3. Pattern is a substring of target domain (loose match)
        4. Profile name matches domain (fallback)
        """
        if not domain:
            return None
        domain_lower = domain.lower().strip()

        # Pass 1: exact match
        for profile in self.profiles.values():
            for d in profile.domains:
                if d.lower().strip() == domain_lower:
                    return profile

        # Pass 2: subdomain match (domain ends with .pattern or pattern ends with .domain)
        for profile in self.profiles.values():
            for d in profile.domains:
                d_lower = d.lower().strip()
                if domain_lower.endswith('.' + d_lower) or d_lower.endswith('.' + domain_lower):
                    return profile

        # Pass 3: loose substring match
        for profile in self.profiles.values():
            for d in profile.domains:
                d_lower = d.lower().strip()
                if d_lower in domain_lower or domain_lower in d_lower:
                    return profile

        # Pass 4: fallback — check profile name
        for name, profile in self.profiles.items():
            if name.lower() in domain_lower or domain_lower in name.lower():
                return profile

        return None

    def get_profile(self, name: str) -> Optional[AuthProfile]:
        """Get a profile by exact name."""
        return self.profiles.get(name)


def load_auth_config(data: dict) -> AuthConfig:
    """
    Load auth config from a YAML-parsed dict. Expected structure:

    auth:
      profiles:
        target1:
          type: cookie
          domains: ["example.com"]
          login_url: "http://example.com/login"
          username: "testuser"
          password: "${TARGET1_PASSWORD}"
          ...
    """
    auth_data = data.get('auth', {})
    if not auth_data:
        return AuthConfig()

    profiles_data = auth_data.get('profiles', {})
    profiles = {}

    for name, pdata in profiles_data.items():
        auth_type_str = pdata.get('type', 'cookie')
        try:
            auth_type = AuthType(auth_type_str)
        except ValueError:
            auth_type = AuthType.COOKIE

        # Build domains list — can be a string or list
        domains_raw = pdata.get('domains', [])
        if isinstance(domains_raw, str):
            domains_raw = [domains_raw]

        profile = AuthProfile(
            name=name,
            auth_type=auth_type,
            domains=domains_raw,
            login_url=pdata.get('login_url'),
            username_field=pdata.get('username_field', 'username'),
            password_field=pdata.get('password_field', 'password'),
            username=pdata.get('username'),
            password=pdata.get('password'),
            extra_fields=pdata.get('extra_fields', {}),
            login_body=pdata.get('body', pdata.get('login_body', {})),
            token_path=pdata.get('token_path', 'token'),
            header=pdata.get('header', 'X-API-Key'),
            key=pdata.get('key'),
            param_name=pdata.get('param_name'),
            token_url=pdata.get('token_url'),
            client_id=pdata.get('client_id'),
            client_secret=pdata.get('client_secret'),
            scope=pdata.get('scope'),
            custom_headers=pdata.get('custom_headers', pdata.get('headers', {})),
            csrf_field=pdata.get('csrf_field'),
            csrf_pattern=pdata.get('csrf_pattern'),
            extra_cookies=pdata.get('extra_cookies', {}),
        )

        # Resolve environment variable placeholders
        profile.resolve_env_vars()

        # Also support top-level env var overrides by convention:
        # RESURFACE_AUTH_{PROFILE_NAME}_{FIELD} (uppercase)
        env_prefix = f"RESURFACE_AUTH_{name.upper()}_"
        for env_field, attr_name in [
            ('USERNAME', 'username'),
            ('PASSWORD', 'password'),
            ('API_KEY', 'key'),
            ('CLIENT_ID', 'client_id'),
            ('CLIENT_SECRET', 'client_secret'),
        ]:
            env_val = os.environ.get(f"{env_prefix}{env_field}", '')
            if env_val:
                setattr(profile, attr_name, env_val)

        profiles[name] = profile

    return AuthConfig(profiles=profiles)
