"""
Authentication Manager — executes auth flows and manages sessions/tokens.

Supports: cookie-based, JWT/bearer, API key, OAuth2 client-credentials, custom header.
Handles automatic re-authentication on 401/403.
Supports auto-auth: LLM-driven autonomous signup/login when no profile exists.
"""
import json
import time
import base64
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from loguru import logger

from src.auth.auth_config import AuthProfile, AuthType, AuthConfig


@dataclass
class AuthSession:
    """Holds active authentication state for a target."""
    profile_name: str
    auth_type: AuthType
    # Cookies captured from login
    cookies: dict[str, str] = field(default_factory=dict)
    # Authorization header value (e.g., "Bearer <token>")
    authorization: Optional[str] = None
    # Extra headers to inject (for custom_header / api_key)
    extra_headers: dict[str, str] = field(default_factory=dict)
    # Extra query params to inject (for api_key in param mode)
    extra_params: dict[str, str] = field(default_factory=dict)
    # Timestamp when the session was created
    authenticated_at: float = 0.0
    # Whether auth succeeded
    success: bool = False
    # Human-readable auth log
    log: str = ""

    def get_headers(self) -> dict[str, str]:
        """Get all headers that should be injected into requests."""
        headers = {}
        if self.cookies:
            cookie_str = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
            headers['Cookie'] = cookie_str
        if self.authorization:
            headers['Authorization'] = self.authorization
        headers.update(self.extra_headers)
        return headers

    def is_stale(self, max_age_seconds: float = 3600) -> bool:
        """Check if session might be expired (default: 1 hour)."""
        if not self.authenticated_at:
            return True
        return (time.time() - self.authenticated_at) > max_age_seconds


class AuthManager:
    """
    Manages authentication flows for vulnerability replay.

    Usage:
        manager = AuthManager(auth_config)
        session = manager.authenticate("example.com")
        # session.get_headers() → inject into requests
    """

    def __init__(self, auth_config: AuthConfig, request_timeout: int = 30):
        self.config = auth_config
        self.timeout = request_timeout
        # Cache active sessions by profile name
        self._sessions: dict[str, AuthSession] = {}

    def authenticate(self, domain: str, profile_name: str = None,
                     force: bool = False) -> Optional[AuthSession]:
        """
        Authenticate against a target domain.

        Args:
            domain: Target domain to authenticate for
            profile_name: Explicit profile name (overrides domain lookup)
            force: Force re-authentication even if cached session exists

        Returns:
            AuthSession on success, None if no profile found
        """
        # Resolve profile
        if profile_name:
            profile = self.config.get_profile(profile_name)
        else:
            profile = self.config.get_profile_for_domain(domain)

        if not profile:
            logger.debug(f"No auth profile found for domain: {domain}")
            return None

        # Check cached session
        if not force and profile.name in self._sessions:
            cached = self._sessions[profile.name]
            if cached.success and not cached.is_stale():
                logger.debug(f"Using cached auth session for {profile.name}")
                return cached

        logger.info(f"🔑 Authenticating with profile '{profile.name}' (type={profile.auth_type.value})")

        session = self._execute_auth_flow(profile)

        if session.success:
            self._sessions[profile.name] = session
            logger.info(f"✅ Authentication successful for '{profile.name}'")
        else:
            logger.warning(f"❌ Authentication failed for '{profile.name}': {session.log}")

        return session

    def get_session(self, domain: str) -> Optional[AuthSession]:
        """Get an existing session for a domain without re-authenticating."""
        profile = self.config.get_profile_for_domain(domain)
        if profile and profile.name in self._sessions:
            return self._sessions[profile.name]
        return None

    def handle_auth_failure(self, domain: str, status_code: int) -> Optional[AuthSession]:
        """
        Handle a 401/403 by re-authenticating once.

        Returns a new session if re-auth succeeded, None otherwise.
        """
        if status_code not in (401, 403):
            return None

        logger.info(f"🔄 Got HTTP {status_code}, attempting re-authentication for {domain}")
        return self.authenticate(domain, force=True)

    def invalidate(self, domain: str = None, profile_name: str = None) -> None:
        """Invalidate a cached session."""
        if profile_name and profile_name in self._sessions:
            del self._sessions[profile_name]
        elif domain:
            profile = self.config.get_profile_for_domain(domain)
            if profile and profile.name in self._sessions:
                del self._sessions[profile.name]

    def get_profile_for_domain(self, domain: str) -> Optional[AuthProfile]:
        """Expose profile lookup for external callers (e.g., browser replayer)."""
        return self.config.get_profile_for_domain(domain)

    def auto_authenticate(
        self,
        target_url: str,
        api_key: str,
        model: str = "gemini-2.0-flash",
        provider: str = "gemini",
        headless: bool = True,
        verbose: bool = False,
    ) -> Optional[AuthSession]:
        """
        Autonomous authentication: LLM-driven signup/login.

        First checks if a manual profile exists for this domain (existing behavior).
        If not, uses AutoAuth to bootstrap credentials via browser automation.

        Args:
            target_url: Full target URL (e.g., "http://localhost:3333")
            api_key: LLM API key (Gemini or Groq)
            model: LLM model name
            provider: "gemini" or "groq"
            headless: Run browser headless
            verbose: Print LLM prompts/responses

        Returns:
            AuthSession on success, None on failure
        """
        from urllib.parse import urlparse

        domain = urlparse(target_url).netloc or urlparse(target_url).path

        # Priority 1: Check if a manual profile exists for this domain
        profile = self.config.get_profile_for_domain(domain)
        if profile:
            logger.info(f"🔑 Manual auth profile found for {domain}: {profile.name}")
            session = self.authenticate(domain)
            if session and session.success:
                return session
            logger.warning(f"⚠️  Manual auth failed for {domain}, falling through to auto-auth")

        # Priority 2: Auto-authenticate using LLM browser automation
        logger.info(f"🤖 Auto-auth: No manual profile for {domain}, starting autonomous auth...")

        try:
            from src.auth.auto_auth import AutoAuth

            auto_auth = AutoAuth(
                api_key=api_key,
                model=model,
                provider=provider,
                headless=headless,
                verbose=verbose,
            )

            result = auto_auth.authenticate(target_url)

            if result.success and result.session:
                # Cache the session in our session store
                self._sessions["auto_auth"] = result.session
                logger.info(f"✅ Auto-auth succeeded for {domain}")
                for line in result.log:
                    logger.debug(f"  auto-auth: {line}")
                return result.session
            else:
                logger.warning(f"❌ Auto-auth failed for {domain}: {result.error}")
                for line in result.log:
                    logger.debug(f"  auto-auth: {line}")
                if result.captcha_detected:
                    logger.warning("  ⚠️  CAPTCHA detected — manual auth required")
                if result.email_verification_required:
                    logger.warning("  ⚠️  Email verification required — manual auth required")
                return None

        except ImportError as e:
            logger.error(f"Auto-auth unavailable (missing dependency): {e}")
            return None
        except Exception as e:
            logger.error(f"Auto-auth error: {e}")
            return None

    # ──────────────────────────────────────────────
    # Auth flow implementations
    # ──────────────────────────────────────────────

    def _execute_auth_flow(self, profile: AuthProfile) -> AuthSession:
        """Dispatch to the appropriate auth flow based on profile type."""
        handlers = {
            AuthType.COOKIE: self._auth_cookie,
            AuthType.JWT: self._auth_jwt,
            AuthType.API_KEY: self._auth_api_key,
            AuthType.OAUTH2: self._auth_oauth2,
            AuthType.CUSTOM_HEADER: self._auth_custom_header,
        }
        handler = handlers.get(profile.auth_type)
        if not handler:
            return AuthSession(
                profile_name=profile.name,
                auth_type=profile.auth_type,
                log=f"Unknown auth type: {profile.auth_type}",
            )
        try:
            return handler(profile)
        except Exception as e:
            logger.error(f"Auth flow error for {profile.name}: {e}")
            return AuthSession(
                profile_name=profile.name,
                auth_type=profile.auth_type,
                log=f"Auth flow exception: {e}",
            )

    def _auth_cookie(self, profile: AuthProfile) -> AuthSession:
        """
        Cookie-based auth: POST login form → capture Set-Cookie headers.

        Supports CSRF tokens: if csrf_field is set (or auto-detected), will
        first GET the login page to extract the token, then include it in POST.
        Supports login_body as an alternative to username_field/password_field.
        Supports extra_cookies to inject additional static cookies.
        """
        import re as _re

        session = AuthSession(
            profile_name=profile.name,
            auth_type=AuthType.COOKIE,
        )

        if not profile.login_url:
            session.log = "No login_url specified for cookie auth"
            return session

        log_lines = []
        cookie_jar = {}

        # ── Step 1: GET login page to capture initial cookies + CSRF token ──
        csrf_token = None
        try:
            get_req = urllib.request.Request(
                profile.login_url,
                headers={'User-Agent': 'Resurface/1.0'},
                method='GET',
            )
            get_resp = urllib.request.urlopen(get_req, timeout=self.timeout)
            html = get_resp.read().decode('utf-8', errors='replace')

            # Capture cookies from GET response (e.g. PHPSESSID)
            for val in get_resp.headers.get_all('Set-Cookie') or []:
                parts = val.split(';')[0]
                if '=' in parts:
                    k, v = parts.split('=', 1)
                    cookie_jar[k.strip()] = v.strip()

            log_lines.append(f"GET {profile.login_url} → cookies: {list(cookie_jar.keys())}")

            # Extract CSRF token from HTML
            csrf_field = profile.csrf_field

            def _extract_csrf(html_src: str, field_name: str) -> str | None:
                """Extract CSRF token value from an <input> tag by field name."""
                if profile.csrf_pattern and field_name == profile.csrf_field:
                    m = _re.search(profile.csrf_pattern, html_src, _re.DOTALL)
                    return (m.group(1) if m else None)
                # Match within a single <input ...> tag (handles any attribute order)
                for tag_match in _re.finditer(r'<input[^>]*>', html_src, _re.IGNORECASE):
                    tag = tag_match.group()
                    if _re.search(rf"""name=['"]{_re.escape(field_name)}['"]""", tag):
                        val_m = _re.search(r"""value=['"](.*?)['"]""", tag)
                        if val_m:
                            return val_m.group(1)
                return None

            if csrf_field:
                csrf_token = _extract_csrf(html, csrf_field)
                if csrf_token:
                    log_lines.append(f"  CSRF token ({csrf_field}): {csrf_token[:16]}...")
                else:
                    log_lines.append(f"  ⚠️  CSRF field '{csrf_field}' not found in login page")
            else:
                # Auto-detect common CSRF token fields
                for field_name in ('user_token', 'csrf_token', '_token', 'csrfmiddlewaretoken', 'authenticity_token'):
                    csrf_token = _extract_csrf(html, field_name)
                    if csrf_token:
                        csrf_field = field_name
                        log_lines.append(f"  Auto-detected CSRF token ({field_name}): {csrf_token[:16]}...")
                        break

        except Exception as e:
            log_lines.append(f"  GET login page error (non-fatal): {e}")

        # ── Step 2: Build form data ──
        if profile.login_body:
            # Use login_body directly (preferred — explicit form fields)
            form_data = dict(profile.login_body)
        else:
            # Fall back to username_field/password_field construction
            form_data = {
                profile.username_field: profile.username or '',
                profile.password_field: profile.password or '',
            }
            form_data.update(profile.extra_fields)

        # Inject CSRF token into form data
        if csrf_token and csrf_field:
            form_data[csrf_field] = csrf_token

        encoded = urllib.parse.urlencode(form_data).encode('utf-8')

        # ── Step 3: POST login form with cookies from GET ──
        post_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Resurface/1.0',
        }
        if cookie_jar:
            post_headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in cookie_jar.items())

        req = urllib.request.Request(
            profile.login_url,
            data=encoded,
            headers=post_headers,
            method='POST',
        )

        form_keys = [k for k in form_data if k not in ('password', profile.password_field)]
        log_lines.append(f"POST {profile.login_url} (fields: {form_keys + ['***']})")

        try:
            class CookieCaptureHandler(urllib.request.HTTPRedirectHandler):
                def http_error_302(self, req, fp, code, msg, headers):
                    self._capture_cookies(headers)
                    return super().http_error_302(req, fp, code, msg, headers)

                http_error_301 = http_error_302
                http_error_303 = http_error_302
                http_error_307 = http_error_302

                def _capture_cookies(self, headers):
                    for val in headers.get_all('Set-Cookie', []):
                        parts = val.split(';')[0]
                        if '=' in parts:
                            k, v = parts.split('=', 1)
                            cookie_jar[k.strip()] = v.strip()

            opener = urllib.request.build_opener(CookieCaptureHandler)
            resp = opener.open(req, timeout=self.timeout)

            # Capture cookies from final response too
            for val in resp.headers.get_all('Set-Cookie') or []:
                parts = val.split(';')[0]
                if '=' in parts:
                    k, v = parts.split('=', 1)
                    cookie_jar[k.strip()] = v.strip()

            status = resp.status
            log_lines.append(f"  response: HTTP {status}")
            log_lines.append(f"  cookies: {list(cookie_jar.keys())}")

            if cookie_jar:
                session.cookies = cookie_jar
                session.success = True
                session.authenticated_at = time.time()
            else:
                if 200 <= status < 400:
                    session.success = True
                    session.authenticated_at = time.time()
                    log_lines.append("  warning: no cookies captured, but login appeared successful")
                else:
                    log_lines.append("  no cookies captured, login may have failed")

        except urllib.error.HTTPError as e:
            log_lines.append(f"  error: HTTP {e.code}")
            for val in e.headers.get_all('Set-Cookie') or []:
                parts = val.split(';')[0]
                if '=' in parts:
                    k, v = parts.split('=', 1)
                    session.cookies[k.strip()] = v.strip()
            if session.cookies:
                session.success = True
                session.authenticated_at = time.time()
        except Exception as e:
            log_lines.append(f"  error: {e}")

        # ── Step 4: Merge extra_cookies (e.g. security=low for DVWA) ──
        if profile.extra_cookies:
            session.cookies.update(profile.extra_cookies)
            log_lines.append(f"  extra cookies: {list(profile.extra_cookies.keys())}")

        session.log = '\n'.join(log_lines)
        return session

    def _auth_jwt(self, profile: AuthProfile) -> AuthSession:
        """
        JWT/Bearer auth: POST JSON to login endpoint → extract token from response.
        """
        session = AuthSession(
            profile_name=profile.name,
            auth_type=AuthType.JWT,
        )

        if not profile.login_url:
            session.log = "No login_url specified for JWT auth"
            return session

        # Build request body — prefer login_body, fall back to username/password
        body = dict(profile.login_body) if profile.login_body else {}
        if not body:
            body = {
                profile.username_field: profile.username or '',
                profile.password_field: profile.password or '',
            }
            body.update(profile.extra_fields)

        payload = json.dumps(body).encode('utf-8')

        req = urllib.request.Request(
            profile.login_url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Resurface/1.0',
            },
            method='POST',
        )

        log_lines = [f"POST {profile.login_url} (JWT)"]

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            resp_body = resp.read().decode('utf-8', errors='replace')
            data = json.loads(resp_body)

            # Extract token using dot-path (e.g., "data.token" or "access_token")
            token = self._extract_json_path(data, profile.token_path)

            if token:
                session.authorization = f"Bearer {token}"
                session.success = True
                session.authenticated_at = time.time()
                log_lines.append(f"  token extracted via path '{profile.token_path}'")
                log_lines.append(f"  token: {token[:20]}...")
            else:
                log_lines.append(f"  failed to extract token at path '{profile.token_path}'")
                log_lines.append(f"  response keys: {list(data.keys()) if isinstance(data, dict) else type(data).__name__}")

        except urllib.error.HTTPError as e:
            log_lines.append(f"  error: HTTP {e.code}")
            try:
                err_body = e.read().decode('utf-8', errors='replace')[:500]
                log_lines.append(f"  body: {err_body}")
            except:
                pass
        except Exception as e:
            log_lines.append(f"  error: {e}")

        session.log = '\n'.join(log_lines)
        return session

    def _auth_api_key(self, profile: AuthProfile) -> AuthSession:
        """
        API key auth: inject a static header or query param. No HTTP call needed.
        """
        session = AuthSession(
            profile_name=profile.name,
            auth_type=AuthType.API_KEY,
        )

        key = profile.key
        if not key:
            session.log = "No API key provided"
            return session

        log_lines = ["API key auth (static)"]

        if profile.param_name:
            # Key goes as query param
            session.extra_params[profile.param_name] = key
            log_lines.append(f"  param: {profile.param_name}=***")
        else:
            # Key goes as header
            header_name = profile.header or 'X-API-Key'
            session.extra_headers[header_name] = key
            log_lines.append(f"  header: {header_name}=***")

        session.success = True
        session.authenticated_at = time.time()
        session.log = '\n'.join(log_lines)
        return session

    def _auth_oauth2(self, profile: AuthProfile) -> AuthSession:
        """
        OAuth2 client-credentials flow: POST to token endpoint → bearer token.
        """
        session = AuthSession(
            profile_name=profile.name,
            auth_type=AuthType.OAUTH2,
        )

        token_url = profile.token_url or profile.login_url
        if not token_url:
            session.log = "No token_url specified for OAuth2 auth"
            return session

        if not profile.client_id or not profile.client_secret:
            session.log = "Missing client_id or client_secret for OAuth2"
            return session

        # Build token request
        form_data = {
            'grant_type': 'client_credentials',
            'client_id': profile.client_id,
            'client_secret': profile.client_secret,
        }
        if profile.scope:
            form_data['scope'] = profile.scope

        encoded = urllib.parse.urlencode(form_data).encode('utf-8')

        # Some providers want Basic auth header with client creds
        basic_auth = base64.b64encode(
            f"{profile.client_id}:{profile.client_secret}".encode()
        ).decode()

        req = urllib.request.Request(
            token_url,
            data=encoded,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': f'Basic {basic_auth}',
                'User-Agent': 'Resurface/1.0',
            },
            method='POST',
        )

        log_lines = [f"POST {token_url} (OAuth2 client_credentials)"]

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            resp_body = resp.read().decode('utf-8', errors='replace')
            data = json.loads(resp_body)

            token = data.get('access_token')
            token_type = data.get('token_type', 'Bearer')

            if token:
                session.authorization = f"{token_type} {token}"
                session.success = True
                session.authenticated_at = time.time()
                log_lines.append(f"  token_type: {token_type}")
                log_lines.append(f"  token: {token[:20]}...")
                if 'expires_in' in data:
                    log_lines.append(f"  expires_in: {data['expires_in']}s")
            else:
                log_lines.append(f"  no access_token in response")
                log_lines.append(f"  response keys: {list(data.keys())}")

        except urllib.error.HTTPError as e:
            log_lines.append(f"  error: HTTP {e.code}")
            try:
                err_body = e.read().decode('utf-8', errors='replace')[:500]
                log_lines.append(f"  body: {err_body}")
            except:
                pass
        except Exception as e:
            log_lines.append(f"  error: {e}")

        session.log = '\n'.join(log_lines)
        return session

    def _auth_custom_header(self, profile: AuthProfile) -> AuthSession:
        """
        Custom header auth: inject arbitrary headers from config. No HTTP call needed.
        """
        session = AuthSession(
            profile_name=profile.name,
            auth_type=AuthType.CUSTOM_HEADER,
        )

        if not profile.custom_headers:
            session.log = "No custom_headers provided"
            return session

        session.extra_headers = dict(profile.custom_headers)
        session.success = True
        session.authenticated_at = time.time()

        header_names = list(profile.custom_headers.keys())
        session.log = f"Custom header auth: injecting {header_names}"
        return session

    # ──────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────

    @staticmethod
    def _extract_json_path(data: dict, path: str):
        """
        Extract a value from a nested dict using a dot-separated path.
        E.g., "data.token" → data["data"]["token"]
        """
        keys = path.split('.')
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
