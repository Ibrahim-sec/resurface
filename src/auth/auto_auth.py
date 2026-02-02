"""
Autonomous Authentication Engine — LLM-driven signup/login without pre-configured credentials.

Uses Playwright + LLM (Gemini/Groq) to:
1. Discover registration/login pages on a target
2. Register a new account with generated credentials
3. Log in and extract auth tokens (cookies, JWT, headers)
4. Return an AuthSession usable by HTTP and browser replayers

Falls back gracefully when CAPTCHA, email verification, or other blockers are detected.
"""
import json
import os
import re
import time
import string
import secrets
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from loguru import logger

from src.auth.auth_manager import AuthSession
from src.auth.auth_config import AuthType


# ──────────────────────────────────────────────
#  LLM Prompts
# ──────────────────────────────────────────────

DISCOVERY_PROMPT = """You are an autonomous web application authentication agent. You are looking at a web page and need to find how to register and log in.

## Current Page State
- **URL:** {url}
- **Title:** {title}
- **Visible Text (first 3000 chars):**
{page_text}

## Your Task
Analyze this page and find:
1. Links or buttons leading to a **registration/signup** page
2. Links or buttons leading to a **login/signin** page
3. Whether there's a registration/login **form already visible** on this page
4. What fields appear to be required (email, username, password, confirm password, etc.)

Respond with JSON:
{{
    "has_login_form": <true if a login form is visible on this page>,
    "has_registration_form": <true if a registration/signup form is visible on this page>,
    "login_link": "<CSS selector or URL for the login link/button, or null>",
    "registration_link": "<CSS selector or URL for the signup/register link/button, or null>",
    "login_fields": ["<field names/types visible in the login form>"],
    "registration_fields": ["<field names/types visible in the registration form>"],
    "captcha_detected": <true if you see a CAPTCHA challenge>,
    "notes": "<any relevant observations about the auth flow>"
}}

Return ONLY valid JSON. If you're unsure about a selector, use a descriptive one like "a:has-text('Sign Up')" or provide the href URL.
"""

REGISTRATION_PROMPT = """You are an autonomous browser agent filling in a registration form.

## Current Page State
- **URL:** {url}
- **Title:** {title}
- **Visible Text (first 3000 chars):**
{page_text}

## Credentials to Use
- **Email:** {email}
- **Username:** {username}
- **Password:** {password}

## Actions Taken So Far
{actions_so_far}

## Your Task
Look at the current page and provide the NEXT browser action to complete the registration.

If the form has fields for:
- Email → use the email above
- Username/user/name → use the username above  
- Password → use the password above
- Confirm/repeat password → use the same password
- Any other required field → use a reasonable value

Respond with JSON:
{{
    "action": "<one of: click, type, select, submit_form, navigate, done>",
    "target": "<CSS selector for the element to interact with>",
    "value": "<text to type, option to select, URL to navigate to, or null>",
    "description": "<what this action does>",
    "is_final_step": <true if registration is complete or this submits the form>,
    "success_detected": <true if you can see a success message, welcome page, or dashboard>,
    "failure_detected": <true if you see an error message about the registration failing>,
    "failure_reason": "<the error message if failure_detected is true, else null>",
    "captcha_detected": <true if a CAPTCHA appeared>
}}

## Rules
- Execute ONE action at a time
- Fill fields in order: email/username first, then password, then submit
- After submitting, check for success/error messages on the resulting page
- If you see "email already exists" or similar, set failure_detected=true
- If you see a welcome message or redirect to dashboard, set success_detected=true
- Return ONLY valid JSON
"""

LOGIN_PROMPT = """You are an autonomous browser agent logging into a web application.

## Current Page State
- **URL:** {url}
- **Title:** {title}
- **Visible Text (first 3000 chars):**
{page_text}

## Credentials to Use
- **Email:** {email}
- **Username:** {username}
- **Password:** {password}

## Actions Taken So Far
{actions_so_far}

## Your Task
Look at the current page and provide the NEXT browser action to log in.

Respond with JSON:
{{
    "action": "<one of: click, type, submit_form, navigate, done>",
    "target": "<CSS selector for the element to interact with>",
    "value": "<text to type, URL to navigate, or null>",
    "description": "<what this action does>",
    "is_final_step": <true if this submits the login form or login is complete>,
    "success_detected": <true if you can see you are logged in (dashboard, welcome, profile, etc.)>,
    "failure_detected": <true if you see a login error>,
    "failure_reason": "<error message if failure_detected, else null>"
}}

## Rules
- Execute ONE action at a time  
- For the login identifier field, try email first; if there's clearly a "username" field, use the username
- After submitting, check for success or error indicators
- Return ONLY valid JSON
"""

TOKEN_EXTRACTION_PROMPT = """You are analyzing a web page after successful authentication to identify auth tokens.

## Current Page State
- **URL:** {url}
- **Title:** {title}
- **Visible Text (first 2000 chars):**
{page_text}

## Cookies Present
{cookies_json}

## LocalStorage Values
{local_storage_json}

## SessionStorage Values
{session_storage_json}

## Captured Network Headers
{captured_headers_json}

## Your Task
Analyze all the data above and identify which items are authentication tokens/credentials.

Respond with JSON:
{{
    "auth_cookies": ["<cookie names that are auth-related (session IDs, tokens, etc.)>"],
    "jwt_token": "<JWT token if found in cookies, localStorage, or headers — the actual token string, or null>",
    "auth_header_value": "<full Authorization header value if found, e.g. 'Bearer eyJ...', or null>",
    "token_location": "<where the primary auth token was found: cookie, localStorage, sessionStorage, header, or null>",
    "session_appears_valid": <true if the data suggests a valid authenticated session>,
    "notes": "<any relevant observations>"
}}

Return ONLY valid JSON.
"""


# ──────────────────────────────────────────────
#  Credential Cache
# ──────────────────────────────────────────────

@dataclass
class CachedCredentials:
    """Cached auto-generated credentials for a target."""
    email: str = ""
    username: str = ""
    password: str = ""
    registered_at: str = ""
    token: Optional[str] = None
    cookies: dict = field(default_factory=dict)
    auth_header: Optional[str] = None


class CredentialCache:
    """Manages persistent credential cache for auto-auth."""

    def __init__(self, cache_path: str = "data/.auto_auth_cache.json"):
        self.cache_path = Path(cache_path)
        self._cache: dict = {}
        self._load()

    def _load(self):
        if self.cache_path.exists():
            try:
                with open(self.cache_path) as f:
                    self._cache = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._cache = {}

    def _save(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, 'w') as f:
            json.dump(self._cache, f, indent=2)

    def get(self, domain: str) -> Optional[CachedCredentials]:
        """Get cached credentials for a domain."""
        data = self._cache.get(domain)
        if not data:
            return None
        return CachedCredentials(
            email=data.get('email', ''),
            username=data.get('username', ''),
            password=data.get('password', ''),
            registered_at=data.get('registered_at', ''),
            token=data.get('token'),
            cookies=data.get('cookies', {}),
            auth_header=data.get('auth_header'),
        )

    def put(self, domain: str, creds: CachedCredentials):
        """Save credentials to cache."""
        self._cache[domain] = {
            'email': creds.email,
            'username': creds.username,
            'password': creds.password,
            'registered_at': creds.registered_at,
            'token': creds.token,
            'cookies': creds.cookies,
            'auth_header': creds.auth_header,
        }
        self._save()

    def remove(self, domain: str):
        """Remove cached credentials for a domain."""
        self._cache.pop(domain, None)
        self._save()


# ──────────────────────────────────────────────
#  Auto-Auth Engine
# ──────────────────────────────────────────────

@dataclass
class AutoAuthResult:
    """Result of an autonomous authentication attempt."""
    success: bool = False
    session: Optional[AuthSession] = None
    credentials: Optional[CachedCredentials] = None
    phase: str = ""  # "discovery", "registration", "login", "token_extraction"
    error: str = ""
    captcha_detected: bool = False
    email_verification_required: bool = False
    log: list = field(default_factory=list)


class AutoAuth:
    """
    LLM-driven autonomous authentication engine.

    Opens a Playwright browser, navigates the target, discovers auth pages,
    registers a new account (or uses cached credentials), logs in, and
    extracts auth tokens — all without any hardcoded selectors.
    """

    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.0-flash",
        provider: str = "gemini",
        headless: bool = True,
        timeout: int = 30000,
        cache_path: str = "data/.auto_auth_cache.json",
        verbose: bool = False,
    ):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.headless = headless
        self.timeout = timeout
        self.verbose = verbose
        self.cache = CredentialCache(cache_path)

    # ──────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────

    def authenticate(self, target_url: str) -> AutoAuthResult:
        """
        Full autonomous authentication flow:
        1. Check credential cache → try login with cached creds
        2. If no cache → discover auth pages → register → login
        3. Extract tokens and return AuthSession

        Args:
            target_url: Base URL of the target application (e.g., "http://localhost:3333")

        Returns:
            AutoAuthResult with session and credentials
        """
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc or urlparse(target_url).path
        result = AutoAuthResult()

        # Phase 0: Check cache
        cached = self.cache.get(domain)
        if cached and cached.email:
            logger.info(f"🤖 Auto-auth: Found cached credentials for {domain}")
            result.log.append(f"Found cached credentials: {cached.email}")

            # Try login with cached credentials
            login_result = self._full_browser_flow(
                target_url, domain, cached, skip_registration=True
            )
            if login_result.success:
                logger.info(f"✅ Auto-auth: Logged in with cached credentials")
                return login_result

            logger.info(f"⚠️  Auto-auth: Cached credentials failed, re-registering...")
            self.cache.remove(domain)

        # Phase 1-3: Full flow (discover → register → login → extract)
        creds = self._generate_credentials()
        result = self._full_browser_flow(target_url, domain, creds, skip_registration=False)

        # Cache on success
        if result.success and result.credentials:
            self.cache.put(domain, result.credentials)
            logger.info(f"💾 Auto-auth: Credentials cached for {domain}")

        return result

    # ──────────────────────────────────────────
    #  Browser Flow
    # ──────────────────────────────────────────

    def _full_browser_flow(
        self,
        target_url: str,
        domain: str,
        creds: CachedCredentials,
        skip_registration: bool = False,
    ) -> AutoAuthResult:
        """Run the complete browser-based auth flow."""
        from playwright.sync_api import sync_playwright

        result = AutoAuthResult(credentials=creds)
        captured_auth_headers: list[dict] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=self.headless,
                args=['--no-sandbox', '--disable-web-security'],
            )
            context = browser.new_context(
                viewport={'width': 1280, 'height': 720},
                ignore_https_errors=True,
            )
            page = context.new_page()

            # Intercept network requests to capture Authorization headers
            def on_request(request):
                auth = request.headers.get('authorization', '')
                if auth:
                    captured_auth_headers.append({
                        'url': request.url,
                        'authorization': auth,
                    })
            page.on('request', on_request)

            try:
                # Phase 1: Discovery
                result.phase = "discovery"
                logger.info(f"🤖 Auto-auth: Discovering auth pages on {target_url}...")
                result.log.append(f"Navigating to {target_url}")

                page.goto(target_url, timeout=self.timeout, wait_until='domcontentloaded')
                time.sleep(1)

                discovery = self._discover_auth_pages(page)
                if not discovery:
                    result.error = "Failed to analyze page for auth discovery"
                    result.log.append("Discovery: LLM analysis failed")
                    browser.close()
                    return result

                result.log.append(f"Discovery: login_form={discovery.get('has_login_form')}, "
                                  f"reg_form={discovery.get('has_registration_form')}, "
                                  f"captcha={discovery.get('captcha_detected')}")

                if discovery.get('captcha_detected'):
                    result.captcha_detected = True
                    result.error = "CAPTCHA detected — manual authentication required"
                    result.log.append("❌ CAPTCHA detected, aborting auto-auth")
                    logger.warning(f"🤖 Auto-auth: CAPTCHA detected on {domain}")
                    browser.close()
                    return result

                # Phase 2: Registration (unless skipped)
                if not skip_registration:
                    result.phase = "registration"
                    reg_link = discovery.get('registration_link')

                    if reg_link:
                        logger.info(f"🤖 Auto-auth: Registering new account on {domain}...")
                        result.log.append(f"Registration link found: {reg_link}")

                        reg_success = self._do_registration(page, creds, reg_link, discovery)

                        if reg_success.get('captcha_detected'):
                            result.captcha_detected = True
                            result.error = "CAPTCHA detected during registration"
                            result.log.append("❌ CAPTCHA during registration")
                            browser.close()
                            return result

                        if reg_success.get('success'):
                            result.log.append("✅ Registration successful")
                            logger.info(f"✅ Auto-auth: Registration successful")
                            creds.registered_at = datetime.now().isoformat()
                        else:
                            failure = reg_success.get('failure_reason', 'Unknown error')
                            result.log.append(f"⚠️ Registration failed: {failure}")
                            logger.warning(f"⚠️ Auto-auth: Registration failed: {failure}")
                            # Don't abort — try login anyway (maybe already registered)
                    else:
                        result.log.append("No registration link found, attempting login only")
                        logger.info("🤖 Auto-auth: No registration link, trying login directly")

                # Phase 3: Login
                result.phase = "login"
                login_link = discovery.get('login_link')

                # Navigate to login page if needed
                if login_link:
                    logger.info(f"🤖 Auto-auth: Logging in on {domain}...")
                    login_success = self._do_login(page, creds, login_link, discovery)
                elif discovery.get('has_login_form'):
                    logger.info(f"🤖 Auto-auth: Login form already visible, logging in...")
                    login_success = self._do_login(page, creds, None, discovery)
                else:
                    # Navigate back to target and try to find login
                    page.goto(target_url, timeout=self.timeout, wait_until='domcontentloaded')
                    time.sleep(1)
                    login_success = self._do_login(page, creds, None, discovery)

                if login_success.get('captcha_detected'):
                    result.captcha_detected = True
                    result.error = "CAPTCHA detected during login"
                    result.log.append("❌ CAPTCHA during login")
                    browser.close()
                    return result

                if not login_success.get('success'):
                    failure = login_success.get('failure_reason', 'Login did not succeed')
                    result.error = f"Login failed: {failure}"
                    result.log.append(f"❌ Login failed: {failure}")
                    logger.warning(f"❌ Auto-auth: Login failed: {failure}")
                    browser.close()
                    return result

                result.log.append("✅ Login successful")
                logger.info(f"✅ Auto-auth: Login successful")

                # Phase 4: Token Extraction
                result.phase = "token_extraction"
                logger.info(f"🤖 Auto-auth: Extracting auth tokens...")

                session = self._extract_tokens(page, context, captured_auth_headers)

                if session and session.success:
                    result.success = True
                    result.session = session

                    # Update cached credentials with extracted token info
                    if session.authorization:
                        creds.auth_header = session.authorization
                        # Extract raw token
                        token_match = re.search(r'Bearer\s+(.+)', session.authorization)
                        if token_match:
                            creds.token = token_match.group(1)
                    if session.cookies:
                        creds.cookies = session.cookies

                    result.credentials = creds
                    result.log.append(f"✅ Tokens extracted: cookies={list(session.cookies.keys())}, "
                                      f"auth_header={'yes' if session.authorization else 'no'}")
                    logger.info(f"✅ Auto-auth: Session established for {domain}")
                else:
                    result.error = "Token extraction failed — no usable auth data found"
                    result.log.append("⚠️ Token extraction: no usable auth data")
                    logger.warning(f"⚠️ Auto-auth: No auth tokens found after login")

            except Exception as e:
                result.error = f"Browser flow error: {e}"
                result.log.append(f"❌ Exception: {e}")
                logger.error(f"❌ Auto-auth error: {e}")

            finally:
                browser.close()

        return result

    # ──────────────────────────────────────────
    #  Phase 1: Discovery
    # ──────────────────────────────────────────

    def _discover_auth_pages(self, page) -> Optional[dict]:
        """Use LLM to analyze the page and find auth-related links/forms."""
        try:
            url = page.url
            title = page.title()
            page_text = page.inner_text('body')[:3000]
        except Exception as e:
            logger.error(f"Failed to read page state: {e}")
            return None

        prompt = DISCOVERY_PROMPT.format(
            url=url,
            title=title,
            page_text=page_text,
        )

        raw = self._call_llm(prompt, label="Auto-Auth Discovery")
        if not raw:
            return None

        return self._parse_json_response(raw)

    # ──────────────────────────────────────────
    #  Phase 2: Registration
    # ──────────────────────────────────────────

    def _do_registration(self, page, creds: CachedCredentials,
                         reg_link: Optional[str], discovery: dict) -> dict:
        """LLM-driven registration flow. Returns status dict."""
        result = {'success': False, 'failure_reason': None, 'captcha_detected': False}

        # Navigate to registration page if we have a link
        if reg_link:
            try:
                if reg_link.startswith('http://') or reg_link.startswith('https://'):
                    page.goto(reg_link, timeout=self.timeout, wait_until='domcontentloaded')
                else:
                    # It's a CSS selector — click it
                    page.click(reg_link, timeout=10000)
                    page.wait_for_load_state('domcontentloaded', timeout=self.timeout)
                time.sleep(1)
            except Exception as e:
                logger.warning(f"Failed to navigate to registration: {e}")
                # Try common registration paths
                base = page.url.rstrip('/')
                for path in ['/#/register', '/register', '/signup', '/sign-up', '/auth/register']:
                    try:
                        page.goto(f"{base}{path}", timeout=self.timeout, wait_until='domcontentloaded')
                        time.sleep(1)
                        break
                    except:
                        continue

        # LLM-driven action loop for registration
        actions_history = []
        for step in range(12):
            try:
                url = page.url
                title = page.title()
                page_text = page.inner_text('body')[:3000]
            except:
                break

            actions_so_far = "None yet" if not actions_history else "\n".join(
                f"  {i+1}. {a}" for i, a in enumerate(actions_history)
            )

            prompt = REGISTRATION_PROMPT.format(
                url=url,
                title=title,
                page_text=page_text,
                email=creds.email,
                username=creds.username,
                password=creds.password,
                actions_so_far=actions_so_far,
            )

            raw = self._call_llm(prompt, label="Auto-Auth Registration")
            if not raw:
                break

            action = self._parse_json_response(raw)
            if not action:
                break

            # Check for detections
            if action.get('captcha_detected'):
                result['captcha_detected'] = True
                return result

            if action.get('success_detected'):
                result['success'] = True
                return result

            if action.get('failure_detected'):
                result['failure_reason'] = action.get('failure_reason', 'Registration error')
                return result

            # Execute the action
            executed = self._execute_action(page, action)
            desc = action.get('description', action.get('action', '?'))
            actions_history.append(f"{action.get('action', '?')}: {desc}")

            if not executed:
                result['failure_reason'] = f"Action failed: {desc}"
                return result

            if action.get('is_final_step'):
                # Wait for page to settle after form submission
                time.sleep(2)
                # Check final state
                try:
                    final_text = page.inner_text('body')[:2000].lower()
                    # Heuristic success indicators
                    success_indicators = [
                        'welcome', 'dashboard', 'profile', 'account created',
                        'registration successful', 'successfully registered',
                        'verify your email', 'confirmation email',
                        'thank you for registering', 'you have been registered',
                    ]
                    failure_indicators = [
                        'already exists', 'already registered', 'already taken',
                        'invalid email', 'password too short', 'password too weak',
                        'registration failed', 'error', 'try again',
                    ]

                    for indicator in success_indicators:
                        if indicator in final_text:
                            if 'verify your email' in final_text or 'confirmation email' in final_text:
                                result['failure_reason'] = 'Email verification required'
                                return result
                            result['success'] = True
                            return result

                    for indicator in failure_indicators:
                        if indicator in final_text:
                            result['failure_reason'] = f"Page contains: '{indicator}'"
                            return result

                    # If URL changed significantly, might be a success redirect
                    if page.url != url:
                        result['success'] = True
                        return result
                except:
                    pass
                break

            time.sleep(0.5)

        # If we exhausted all steps, check if we ended up somewhere useful
        try:
            final_url = page.url
            if '/dashboard' in final_url or '/home' in final_url or '/profile' in final_url:
                result['success'] = True
        except:
            pass

        return result

    # ──────────────────────────────────────────
    #  Phase 3: Login
    # ──────────────────────────────────────────

    def _do_login(self, page, creds: CachedCredentials,
                  login_link: Optional[str], discovery: dict) -> dict:
        """LLM-driven login flow. Returns status dict."""
        result = {'success': False, 'failure_reason': None, 'captcha_detected': False}

        # Navigate to login page if we have a link
        if login_link:
            try:
                if login_link.startswith('http://') or login_link.startswith('https://'):
                    page.goto(login_link, timeout=self.timeout, wait_until='domcontentloaded')
                else:
                    page.click(login_link, timeout=10000)
                    page.wait_for_load_state('domcontentloaded', timeout=self.timeout)
                time.sleep(1)
            except Exception as e:
                logger.warning(f"Failed to navigate to login: {e}")
                # Try common login paths
                base = page.url.split('#')[0].rstrip('/')
                for path in ['/#/login', '/login', '/signin', '/sign-in', '/auth/login']:
                    try:
                        page.goto(f"{base}{path}", timeout=self.timeout, wait_until='domcontentloaded')
                        time.sleep(1)
                        break
                    except:
                        continue

        # LLM-driven action loop for login
        actions_history = []
        for step in range(10):
            try:
                url = page.url
                title = page.title()
                page_text = page.inner_text('body')[:3000]
            except:
                break

            actions_so_far = "None yet" if not actions_history else "\n".join(
                f"  {i+1}. {a}" for i, a in enumerate(actions_history)
            )

            prompt = LOGIN_PROMPT.format(
                url=url,
                title=title,
                page_text=page_text,
                email=creds.email,
                username=creds.username,
                password=creds.password,
                actions_so_far=actions_so_far,
            )

            raw = self._call_llm(prompt, label="Auto-Auth Login")
            if not raw:
                break

            action = self._parse_json_response(raw)
            if not action:
                break

            if action.get('captcha_detected'):
                result['captcha_detected'] = True
                return result

            if action.get('success_detected'):
                result['success'] = True
                return result

            if action.get('failure_detected'):
                result['failure_reason'] = action.get('failure_reason', 'Login error')
                return result

            executed = self._execute_action(page, action)
            desc = action.get('description', action.get('action', '?'))
            actions_history.append(f"{action.get('action', '?')}: {desc}")

            if not executed:
                # Don't abort on action failure, let LLM adapt
                pass

            if action.get('is_final_step'):
                time.sleep(2)
                # Check final state
                try:
                    final_text = page.inner_text('body')[:2000].lower()
                    final_url = page.url

                    login_success_indicators = [
                        'welcome', 'dashboard', 'profile', 'logout', 'sign out',
                        'my account', 'your account', 'settings',
                    ]
                    login_failure_indicators = [
                        'invalid credentials', 'wrong password', 'login failed',
                        'incorrect', 'invalid email', 'invalid password',
                        'account not found', 'unauthorized',
                    ]

                    for indicator in login_failure_indicators:
                        if indicator in final_text:
                            result['failure_reason'] = f"Login error: '{indicator}'"
                            return result

                    for indicator in login_success_indicators:
                        if indicator in final_text:
                            result['success'] = True
                            return result

                    # URL changed → likely login succeeded
                    if final_url != url and '/login' not in final_url.lower():
                        result['success'] = True
                        return result
                except:
                    pass
                break

            time.sleep(0.5)

        # Exhausted steps — check if we're logged in by heuristics
        try:
            final_text = page.inner_text('body')[:2000].lower()
            if 'logout' in final_text or 'sign out' in final_text:
                result['success'] = True
        except:
            pass

        return result

    # ──────────────────────────────────────────
    #  Phase 4: Token Extraction
    # ──────────────────────────────────────────

    def _extract_tokens(self, page, context, captured_auth_headers: list) -> Optional[AuthSession]:
        """Extract auth tokens from browser state after login."""
        session = AuthSession(
            profile_name="auto_auth",
            auth_type=AuthType.COOKIE,
        )

        # 1. Extract cookies from browser context
        try:
            browser_cookies = context.cookies()
            for cookie in browser_cookies:
                session.cookies[cookie['name']] = cookie['value']
        except Exception as e:
            logger.debug(f"Cookie extraction error: {e}")

        # 2. Extract localStorage and sessionStorage
        local_storage = {}
        session_storage = {}
        try:
            local_storage = page.evaluate("""() => {
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            }""")
        except Exception as e:
            logger.debug(f"localStorage extraction error: {e}")

        try:
            session_storage = page.evaluate("""() => {
                const items = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key);
                }
                return items;
            }""")
        except Exception as e:
            logger.debug(f"sessionStorage extraction error: {e}")

        # 3. Look for JWT tokens in all sources
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

        # Check cookies for JWTs
        for name, value in session.cookies.items():
            if jwt_pattern.search(value):
                session.authorization = f"Bearer {value}"
                session.auth_type = AuthType.JWT
                logger.info(f"  🔑 JWT found in cookie: {name}")
                break

        # Check localStorage for JWTs
        if not session.authorization:
            for key, value in local_storage.items():
                if isinstance(value, str):
                    match = jwt_pattern.search(value)
                    if match:
                        session.authorization = f"Bearer {match.group(0)}"
                        session.auth_type = AuthType.JWT
                        logger.info(f"  🔑 JWT found in localStorage: {key}")
                        break

        # Check sessionStorage for JWTs
        if not session.authorization:
            for key, value in session_storage.items():
                if isinstance(value, str):
                    match = jwt_pattern.search(value)
                    if match:
                        session.authorization = f"Bearer {match.group(0)}"
                        session.auth_type = AuthType.JWT
                        logger.info(f"  🔑 JWT found in sessionStorage: {key}")
                        break

        # Check captured network headers
        if not session.authorization and captured_auth_headers:
            for header_info in captured_auth_headers:
                auth_val = header_info.get('authorization', '')
                if auth_val.startswith('Bearer ') or jwt_pattern.search(auth_val):
                    session.authorization = auth_val
                    session.auth_type = AuthType.JWT
                    logger.info(f"  🔑 Auth header captured from network request")
                    break

        # 4. Use LLM for deeper analysis if we haven't found clear auth data
        if not session.authorization and len(session.cookies) < 2:
            try:
                page_text = page.inner_text('body')[:2000]
                url = page.url
                title = page.title()
            except:
                page_text = ""
                url = ""
                title = ""

            prompt = TOKEN_EXTRACTION_PROMPT.format(
                url=url,
                title=title,
                page_text=page_text,
                cookies_json=json.dumps(dict(list(session.cookies.items())[:20]), indent=2),
                local_storage_json=json.dumps(dict(list(local_storage.items())[:20]), indent=2),
                session_storage_json=json.dumps(dict(list(session_storage.items())[:20]), indent=2),
                captured_headers_json=json.dumps(captured_auth_headers[:10], indent=2),
            )

            raw = self._call_llm(prompt, label="Auto-Auth Token Extraction")
            if raw:
                analysis = self._parse_json_response(raw)
                if analysis:
                    # If LLM identified a JWT we missed
                    if analysis.get('jwt_token') and not session.authorization:
                        session.authorization = f"Bearer {analysis['jwt_token']}"
                        session.auth_type = AuthType.JWT

                    if analysis.get('auth_header_value') and not session.authorization:
                        session.authorization = analysis['auth_header_value']
                        session.auth_type = AuthType.JWT

                    # If LLM identified auth cookies
                    auth_cookie_names = analysis.get('auth_cookies', [])
                    if auth_cookie_names:
                        logger.info(f"  🔑 LLM identified auth cookies: {auth_cookie_names}")

        # Determine success: we need at least cookies or an auth header
        if session.cookies or session.authorization:
            session.success = True
            session.authenticated_at = time.time()
            session.log = (
                f"Auto-auth session: {len(session.cookies)} cookies, "
                f"auth_header={'yes' if session.authorization else 'no'}"
            )
        else:
            session.log = "No auth data extracted"

        return session

    # ──────────────────────────────────────────
    #  Browser Action Executor
    # ──────────────────────────────────────────

    def _execute_action(self, page, action: dict) -> bool:
        """Execute a single browser action from LLM guidance."""
        action_type = action.get('action', '')
        target = action.get('target', '')
        value = action.get('value', '')

        try:
            if action_type == 'navigate':
                url = value or target
                logger.debug(f"  🌐 Navigate: {url}")
                page.goto(url, timeout=self.timeout, wait_until='domcontentloaded')
                return True

            elif action_type == 'click':
                logger.debug(f"  🖱️ Click: {target}")
                page.click(target, timeout=10000)
                time.sleep(0.5)
                return True

            elif action_type == 'type':
                logger.debug(f"  ⌨️ Type: {target} = {value[:20]}...")
                # Clear field first, then fill
                try:
                    page.fill(target, value, timeout=10000)
                except:
                    # Fallback: click then type
                    page.click(target, timeout=5000)
                    page.keyboard.press('Control+a')
                    page.keyboard.type(value, delay=30)
                return True

            elif action_type == 'select':
                logger.debug(f"  📋 Select: {target} = {value}")
                page.select_option(target, value, timeout=10000)
                return True

            elif action_type == 'submit_form':
                logger.debug(f"  📤 Submit: {target}")
                try:
                    if target:
                        page.evaluate(f"document.querySelector('{target}').submit()")
                    else:
                        page.evaluate("document.querySelector('form').submit()")
                except:
                    try:
                        selector = f"{target} " if target else ""
                        page.click(
                            f"{selector}[type='submit'], {selector}button[type='submit'], "
                            f"{selector}button:has-text('Submit'), {selector}button:has-text('Register'), "
                            f"{selector}button:has-text('Sign'), {selector}button:has-text('Log'), "
                            f"{selector}input[type='submit']",
                            timeout=5000,
                        )
                    except:
                        page.keyboard.press('Enter')
                try:
                    page.wait_for_load_state('domcontentloaded', timeout=10000)
                except:
                    pass
                return True

            elif action_type == 'done':
                return True

            else:
                logger.warning(f"  Unknown action type: {action_type}")
                return False

        except Exception as e:
            logger.warning(f"  ⚠️ Action '{action_type}' failed: {e}")
            return False

    # ──────────────────────────────────────────
    #  Credential Generation
    # ──────────────────────────────────────────

    @staticmethod
    def _generate_credentials() -> CachedCredentials:
        """Generate random but realistic credentials for registration."""
        rand_suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        return CachedCredentials(
            email=f"resurface_test_{rand_suffix}@protonmail.com",
            username=f"resurface_tester_{rand_suffix}",
            password=f"Resrf@ce_T3st!{rand_suffix}",
        )

    # ──────────────────────────────────────────
    #  LLM Communication
    # ──────────────────────────────────────────

    def _call_llm(self, prompt: str, max_retries: int = 3,
                  label: str = "Auto-Auth") -> Optional[str]:
        """Call LLM API (Gemini or Groq) with retry. Same pattern as BrowserReplayer."""
        if self.verbose:
            try:
                from src.utils.verbose import print_llm_prompt
                print_llm_prompt(prompt, label=label)
            except ImportError:
                pass

        for attempt in range(max_retries):
            try:
                if self.provider == "groq":
                    result = self._call_groq(prompt)
                else:
                    result = self._call_gemini(prompt)

                if self.verbose and result:
                    try:
                        from src.utils.verbose import print_llm_response
                        print_llm_response(result, label=label)
                    except ImportError:
                        pass

                return result

            except urllib.error.HTTPError as e:
                if e.code == 429:
                    wait = (2 ** attempt) * 5
                    logger.warning(f"Rate limited. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                logger.error(f"LLM call failed: HTTP {e.code}")
                return None
            except Exception as e:
                logger.error(f"LLM call failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                return None
        return None

    def _call_gemini(self, prompt: str) -> Optional[str]:
        """Call Gemini API."""
        url = self.GEMINI_URL.format(model=self.model) + f"?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json",
            },
        }
        req = urllib.request.Request(url, headers={'Content-Type': 'application/json'})
        req.data = json.dumps(payload).encode()
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read())
        candidates = data.get('candidates', [])
        if candidates:
            parts = candidates[0].get('content', {}).get('parts', [])
            if parts:
                return parts[0].get('text', '')
        return None

    def _call_groq(self, prompt: str) -> Optional[str]:
        """Call Groq API."""
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 2048,
            "response_format": {"type": "json_object"},
        }
        req = urllib.request.Request(self.GROQ_URL, headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Resurface/1.0',
            'Authorization': f'Bearer {self.api_key}',
        })
        req.data = json.dumps(payload).encode()
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read())
        choices = data.get('choices', [])
        if choices:
            return choices[0].get('message', {}).get('content', '')
        return None

    @staticmethod
    def _parse_json_response(raw: str) -> Optional[dict]:
        """Parse JSON from LLM response, handling markdown fences."""
        try:
            text = raw.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1]
                text = text.rsplit('```', 1)[0]
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            try:
                start = raw.index('{')
                end = raw.rindex('}') + 1
                return json.loads(raw[start:end])
            except (ValueError, json.JSONDecodeError):
                logger.error(f"Failed to parse LLM JSON response: {raw[:200]}")
                return None
