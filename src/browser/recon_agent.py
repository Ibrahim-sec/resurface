"""
Smart Recon Agent — LLM-powered site reconnaissance for surgical vulnerability testing.

Phase 1 of the two-phase approach:
  Phase 1 (this module): Pure exploration — NO payloads, NO attacks.
    Uses browser-use Agent to navigate and semantically UNDERSTAND a target site.
    Outputs a detailed site map with pages, forms, APIs, auth flows, tech stack.

  Phase 2 (BrowserUseReplayer): Surgical attack using recon knowledge.
    Receives the ReconResult.to_attack_prompt() as context → skips exploration,
    goes straight to the highest-value targets.

Unlike SiteCache.crawl() which is a dumb Playwright crawler extracting DOM elements,
this agent uses an LLM to understand WHAT pages do, HOW auth works, and WHERE
the interesting attack surface is.
"""

import asyncio
import json
import os
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from loguru import logger

from src.browser import DEFAULT_CHROME_ARGS
from src.browser.site_cache import SiteCache, EXTRACT_ELEMENTS_JS
from src.auth.auth_manager import AuthManager, AuthSession


# ─────────────────────────────────────────────────────────────────────
# ReconResult — structured output of a recon run
# ─────────────────────────────────────────────────────────────────────

@dataclass
class ReconResult:
    """
    Result of a recon run.

    Contains the full site map discovered by the LLM recon agent, plus
    helpers to persist to SiteCache, export as JSON, and generate rich
    context prompts for the attack agent.
    """

    target_url: str
    site_map: dict  # The full site_map dict (pages, forms, api_endpoints, etc.)
    screenshots: list[str] = field(default_factory=list)
    duration: float = 0.0
    actions_taken: int = 0
    error: Optional[str] = None

    # ── Property accessors ───────────────────────────────────────

    @property
    def pages(self) -> list[dict]:
        return self.site_map.get("pages", [])

    @property
    def forms(self) -> list[dict]:
        return self.site_map.get("forms", [])

    @property
    def api_endpoints(self) -> list[dict]:
        return self.site_map.get("api_endpoints", [])

    @property
    def auth_flow(self) -> dict:
        return self.site_map.get("auth_flow", {})

    # ── Persistence ──────────────────────────────────────────────

    def save_to_cache(self, site_cache: SiteCache, target_url: str):
        """Persist recon results into SiteCache format for cross-module use."""
        data = site_cache._ensure_data(target_url)

        # Add pages as routes
        for page in self.pages:
            route = page["url"]
            if route not in data.get("routes", {}):
                data.setdefault("routes", {})[route] = {
                    "title": page.get("title", ""),
                    "description": page.get("description", ""),
                    "page_type": page.get("page_type", "content"),
                    "elements": [],
                    "inspected_at": page.get("discovered_at"),
                }

        # Add forms as elements under their routes
        for form in self.forms:
            route = form["page_url"]
            if route in data.get("routes", {}):
                data["routes"][route].setdefault("forms", []).append({
                    "action": form["action"],
                    "method": form["method"],
                    "fields": form["fields_raw"],
                    "submit_button": form.get("submit_button", ""),
                })

        # Add API endpoints
        for ep in self.api_endpoints:
            key = f"{ep['method']} {ep['endpoint']}"
            data.setdefault("api_endpoints", {})[key] = {
                "method": ep["method"],
                "endpoint": ep["endpoint"],
                "description": ep.get("description", ""),
                "params": ep.get("params", ""),
            }

        # Add auth flow
        if self.auth_flow:
            data["auth_flow"] = self.auth_flow

        # Add tech stack
        if self.site_map.get("tech_stack"):
            data["tech_stack"] = self.site_map["tech_stack"]

        # Add navigation
        if self.site_map.get("navigation"):
            data["navigation"] = self.site_map["navigation"]

        # Add notes
        if self.site_map.get("notes"):
            data["recon_notes"] = self.site_map["notes"]

        # Mark as LLM-reconned
        data["recon_type"] = "llm_agent"
        data["recon_at"] = time.time()

        site_cache.save(target_url, data)

    # ── Attack Prompt Generation ─────────────────────────────────

    def to_attack_prompt(self, vuln_type: str = None) -> str:
        """
        Generate a detailed site knowledge section for the attack agent prompt.

        This is the bridge between Phase 1 (recon) and Phase 2 (attack).
        Much richer than what SiteCache.get_prompt_context() produces because
        it includes semantic understanding from the LLM — not just DOM elements.
        """
        sections: list[str] = []
        sections.append("## APPLICATION KNOWLEDGE (from recon)")
        sections.append(f"Target: {self.target_url}")

        # Tech stack
        if self.site_map.get("tech_stack"):
            sections.append(f"Tech stack: {', '.join(self.site_map['tech_stack'])}")

        # Auth flow
        if self.auth_flow:
            af = self.auth_flow
            sections.append("\n### Authentication")
            sections.append(f"Type: {af.get('auth_type', 'unknown')}")
            sections.append(f"Login URL: {af.get('login_url', 'unknown')}")
            sections.append(f"Fields: {af.get('fields', 'unknown')}")
            if af.get("notes"):
                sections.append(f"Notes: {af['notes']}")

        # Pages discovered
        if self.pages:
            sections.append(f"\n### Pages Discovered ({len(self.pages)})")
            for p in self.pages:
                page_type = p.get("page_type", "content")
                desc = p.get("description", "")[:100]
                sections.append(f"- [{page_type.upper()}] {p['url']} — {desc}")

        # Forms
        if self.forms:
            sections.append(f"\n### Forms ({len(self.forms)})")
            for f in self.forms:
                sections.append(f"- {f['method']} {f['action']} on {f['page_url']}")
                sections.append(f"  Fields: {f['fields_raw']}")

        # API endpoints
        if self.api_endpoints:
            sections.append(f"\n### API Endpoints ({len(self.api_endpoints)})")
            for ep in self.api_endpoints:
                desc = ep.get("description", "")
                sections.append(f"- {ep['method']} {ep['endpoint']} — {desc}")

        # Relevant notes
        if self.site_map.get("notes"):
            relevant = self.site_map["notes"]
            if vuln_type:
                security_notes = [
                    n for n in relevant
                    if n.get("category") in ("security", "interesting")
                ]
                if security_notes:
                    relevant = security_notes
            if relevant:
                sections.append("\n### Agent Notes")
                for n in relevant[:10]:
                    cat = n.get("category", "general")
                    sections.append(f"- [{cat}] {n['note']}")

        # Targeting advice for a specific vuln type
        if vuln_type:
            relevant_pages = self._find_relevant_pages(vuln_type)
            if relevant_pages:
                sections.append(f"\n### RECOMMENDED TARGETS for {vuln_type}")
                for p in relevant_pages:
                    desc = p.get("description", "")
                    sections.append(f"- START HERE: {p['url']} — {desc}")

        return "\n".join(sections)

    def _find_relevant_pages(self, vuln_type: str) -> list[dict]:
        """Find pages most relevant to a given vulnerability type."""
        relevance_map = {
            "xss_reflected": ["search", "content"],
            "xss_stored": ["content", "profile", "settings"],
            "xss_dom": ["search", "content"],
            "sqli": ["login", "search", "content"],
            "idor": ["profile", "api_docs", "content"],
            "privilege_escalation": ["register", "profile", "admin", "settings"],
            "info_disclosure": ["api_docs", "admin", "settings", "error"],
            "broken_access_control": ["admin", "settings", "profile"],
            "path_traversal": ["content"],
            "open_redirect": ["login", "content"],
            "auth_bypass": ["login"],
            "csrf": ["profile", "settings"],
            "ssrf": ["content", "api_docs"],
            "rce": ["admin", "content", "api_docs"],
        }
        target_types = relevance_map.get(vuln_type, ["content"])
        relevant = [p for p in self.pages if p.get("page_type") in target_types]

        # Also match by keywords in description/title
        keywords = vuln_type.replace("_", " ").split()
        for p in self.pages:
            desc = (p.get("description", "") + " " + p.get("title", "")).lower()
            if any(kw in desc for kw in keywords) and p not in relevant:
                relevant.append(p)

        return relevant[:5]

    # ── Serialization ────────────────────────────────────────────

    def summary(self) -> str:
        """One-line summary."""
        return (
            f"Recon: {len(self.pages)} pages, {len(self.forms)} forms, "
            f"{len(self.api_endpoints)} APIs, {self.duration:.1f}s"
        )

    def to_dict(self) -> dict:
        """Serialize for JSON export."""
        return {
            "target_url": self.target_url,
            "site_map": self.site_map,
            "screenshots": self.screenshots,
            "duration": self.duration,
            "actions_taken": self.actions_taken,
            "error": self.error,
        }

    def save_json(self, path: str = None) -> str:
        """Save to JSON file for inspection."""
        if not path:
            Path("data/site_cache").mkdir(parents=True, exist_ok=True)
            safe_name = (
                self.target_url.replace("://", "_")
                .replace("/", "_")
                .replace(":", "_")
            )
            path = f"data/site_cache/{safe_name}_recon.json"
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        return path


# ─────────────────────────────────────────────────────────────────────
# ReconAgent — LLM-driven browser reconnaissance
# ─────────────────────────────────────────────────────────────────────

class ReconAgent:
    """
    LLM-powered site reconnaissance agent.

    Phase 1: Explore the target website using browser-use agent.
    The agent navigates pages, identifies forms, buttons, APIs, auth flows,
    and builds a comprehensive site map. NO attacking, NO payloads.

    Output: A ReconResult with structured site knowledge that can be:
    - Saved to SiteCache for persistent storage
    - Injected into attack agent prompts for Phase 2
    - Exported as JSON for inspection

    Usage:
        agent = ReconAgent(api_key="gsk_...", provider="groq")
        result = agent.recon("http://localhost:3333")
        print(result.summary())

        # Save for persistence
        result.save_json()

        # Generate context for attack agent
        attack_context = result.to_attack_prompt(vuln_type="xss_reflected")
    """

    def __init__(
        self,
        api_key: str,
        model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
        provider: str = "groq",
        headless: bool = True,
        auth_manager: Optional[AuthManager] = None,
        verbose: bool = False,
        cache_dir: str = "data/site_cache",
        groq_api_key: Optional[str] = None,
        claude_api_key: Optional[str] = None,
    ):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.headless = headless
        self.auth_manager = auth_manager
        self.verbose = verbose
        self.site_cache = SiteCache(cache_dir=cache_dir)
        self.groq_api_key = groq_api_key or (api_key if provider == "groq" else None)
        self.claude_api_key = claude_api_key or (api_key if provider == "claude" else None)

    # ── LLM Factory ──────────────────────────────────────────────

    def _create_llm(self):
        """Create LLM for recon — prefer cheap/free models (Groq)."""
        if self.provider == "claude":
            from browser_use.llm import ChatAnthropic
            os.environ["ANTHROPIC_API_KEY"] = self.claude_api_key or ""
            return ChatAnthropic(model=self.model)
        elif self.provider == "groq":
            from browser_use.llm import ChatGroq
            os.environ["GROQ_API_KEY"] = self.groq_api_key or ""
            return ChatGroq(model=self.model)
        elif self.provider == "gemini":
            from browser_use.llm import ChatGoogle
            return ChatGoogle(model=self.model, api_key=self.api_key)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    # ── Recon Prompt ─────────────────────────────────────────────

    def _build_recon_prompt(
        self, target_url: str, focus_areas: Optional[list[str]] = None
    ) -> str:
        """
        Build the recon task prompt — the MOST important piece.

        This prompt instructs the LLM agent to systematically explore
        and document every aspect of the target application without
        injecting any payloads or performing any attacks.
        """

        # Build focus area emphasis
        focus_section = ""
        if focus_areas:
            focus_items = "\n".join(f"  - **{area}**" for area in focus_areas)
            focus_section = (
                f"\n## PRIORITY FOCUS AREAS\n"
                f"Pay extra attention to discovering and documenting:\n"
                f"{focus_items}\n"
                f"Spend more time on these areas. Be extra thorough.\n"
            )

        prompt = f"""You are a web application reconnaissance agent. Your ONLY job is to explore and document the target website. You are building a site map that a security tester will use later.

## TARGET
{target_url}

## CRITICAL RULES
- You are doing RECONNAISSANCE ONLY — pure observation and documentation.
- Do NOT inject any payloads (no <script>, no ' OR 1=1, no ../etc/passwd, nothing).
- Do NOT test for vulnerabilities. Do NOT try to break anything.
- Do NOT submit forms with attack data. Do NOT manipulate parameters maliciously.
- You ARE allowed to click buttons, follow links, and read pages — that's exploration.
- You ARE allowed to view page source, read error messages, and note technologies.
- If you encounter a login form, document it but do NOT try to brute force or bypass it.
- Be SYSTEMATIC: visit every page, document every form, note every link.
{focus_section}
## STEP-BY-STEP PROCEDURE

### Step 1: Initial Landing & Cleanup
1. Navigate to {target_url}
2. IMMEDIATELY look for and dismiss:
   - Cookie consent banners (click "Accept", "OK", "I agree", "Me want it!", "Got it")
   - Welcome/intro modals (click "Close", "X", "Dismiss", "Skip")
   - Notification permission popups (click "Block" or dismiss)
   - Newsletter signup popups (close them)
   - Any overlay that blocks the page content
3. Wait for the page to fully load
4. Call `log_page` with the landing page URL, title, and a description of what the app appears to be

### Step 2: Technology & Framework Detection
Look for indicators of the tech stack:
- Check the page source for framework signatures:
  - Angular: `ng-app`, `ng-controller`, `angular.js`, `zone.js`
  - React: `react`, `data-reactroot`, `__REACT_DEVTOOLS`
  - Vue: `v-bind`, `v-model`, Vue.js script tags
  - jQuery: `jquery.js`, `$.ajax`
  - Bootstrap: `bootstrap.css`, `bootstrap.js`
  - Express/Node: `X-Powered-By: Express` header clues
- Check for CMS indicators: WordPress (`wp-content`), Drupal, Joomla
- Note JavaScript frameworks, CSS frameworks, server technologies
- Check for SPA (Single Page Application) indicators: hash routing (`/#/`), client-side routing
- Call `log_note` with category="tech_stack" for EACH technology you identify

### Step 3: Navigation Discovery
1. Identify the main navigation menu/bar
2. List ALL menu items, links, and navigation elements visible on the page
3. Call `log_nav` for EACH navigation item with its text and URL
4. Look for:
   - Top/header navigation bar
   - Sidebar menus
   - Footer links
   - Hamburger/mobile menus (click to expand them)
   - Breadcrumb navigation
   - Secondary navigation (sub-menus, dropdowns)
5. Check for hidden routes:
   - Links in page source that aren't visible in the UI
   - JavaScript that references routes (e.g., Angular routes, React Router paths)
   - Hash-based routes (/#/login, /#/admin, /#/register)

### Step 4: Systematic Page Exploration
Visit EACH distinct page/route discovered in Step 3. For each page:

1. **Navigate to the page** — wait for it to fully load
2. **Call `log_page`** with:
   - `url`: The full URL or route (e.g., "{target_url}/#/login")
   - `title`: The page title or heading
   - `description`: A semantic description — what does this page DO? What is its purpose?
     Examples: "User login form with email and password fields",
              "Product catalog showing juice products with search and filter",
              "User registration with email, password, security question"
   - `page_type`: One of: login, register, search, admin, profile, settings, api_docs, content, error

3. **Document ALL forms** on the page:
   - For each `<form>` or form-like structure (could be Angular/React forms without <form> tags):
     - Identify the form action/submission URL
     - Identify the HTTP method (GET/POST)
     - List ALL input fields with their:
       - Field name (name attribute or label text)
       - Input type (text, password, email, number, file, hidden, checkbox, radio, select, textarea)
       - Whether the field is required
       - Placeholder text if any
       - Any validation patterns visible
     - Identify the submit button text
   - Call `log_form` for EACH form found
   - Field format: "fieldname(type,required), fieldname2(type), fieldname3(type,placeholder='hint')"
   - Example: "email(email,required), password(password,required), passwordRepeat(password,required), securityQuestion(select), securityAnswer(text,required)"

4. **Look for API calls** in the page:
   - Check for fetch/XHR URLs in JavaScript
   - Look for API endpoints referenced in links or forms
   - Note any REST/GraphQL patterns (e.g., /api/Users, /rest/products, /graphql)
   - Check for API documentation links (/swagger, /api-docs, /openapi)
   - Call `log_api` for each discovered endpoint

5. **Note interesting observations**:
   - Error messages that reveal information
   - Debug/development artifacts
   - Comments in HTML source
   - Exposed configuration
   - Call `log_note` with appropriate category

### Step 5: Authentication Flow Analysis
1. Find the login page/form
2. Document the complete auth flow:
   - What credentials are needed (email+password? username+password? OAuth?)
   - Is there a registration page?
   - Is there a "forgot password" flow?
   - Are there social login options (Google, GitHub, etc.)?
   - Is there MFA/2FA?
   - Does login redirect somewhere specific?
3. Call `log_auth` with:
   - `auth_type`: form_login, oauth, api_key, jwt, cookie, basic
   - `login_url`: The URL of the login page
   - `fields`: Comma-separated credential fields (e.g., "email(email,required), password(password,required)")
   - `notes`: Any extra observations (redirects, error messages, CSRF tokens, etc.)

### Step 6: High-Value Target Discovery
Specifically seek out these page types (they're often the most interesting for security testing):

1. **Search functionality**: Forms or pages where user input is reflected back
   - Search bars, filter inputs, query parameters
   - Note: these are prime XSS targets

2. **File upload forms**: Any form that accepts file uploads
   - What file types are accepted?
   - What's the upload endpoint?
   - Is there a file size limit?

3. **Admin/management pages**: Restricted areas
   - Try navigating to common admin routes: /admin, /#/administration, /dashboard, /manage
   - Document whether they're accessible or return an error

4. **User profile/account pages**: Areas with user-specific data
   - Profile edit forms
   - Account settings
   - Password change forms

5. **API documentation**: Swagger, OpenAPI, API docs
   - Try: /swagger, /api-docs, /openapi.json, /swagger-ui.html, /api/swagger
   - If found, document all listed endpoints

6. **Error pages**: Intentionally trigger 404s or other errors
   - Navigate to a non-existent route (e.g., {target_url}/nonexistent-page-12345)
   - Note what the error page reveals (stack traces, framework info, debug mode)

### Step 7: Final Review
1. Review your findings — did you miss any pages from the navigation?
2. Check if there are any routes you discovered but didn't visit
3. Make sure every form has been documented with ALL its fields
4. Call `log_note` with category="general" for any overall observations about the application

## USING YOUR TOOLS
You MUST use these tools to record findings. If you don't call them, your observations are LOST.

- `log_page(url, title, description, page_type)` — Call for EVERY page you visit
- `log_form(page_url, form_action, method, fields, submit_button)` — Call for EVERY form
- `log_api(endpoint, method, description, params)` — Call for discovered API endpoints
- `log_auth(auth_type, login_url, fields, notes)` — Call once for the auth flow
- `log_note(note, category)` — Call for tech stack, security observations, interesting finds
- `log_nav(text, url, section)` — Call for navigation menu items

## EFFICIENCY
- Don't waste actions on pages you've already documented
- If a page requires login and you can't access it, just note that and move on
- Focus on breadth (cover all pages) before depth (every detail of one page)
- Target: document at least 5-10 pages, all visible forms, and the auth flow
- Be concise but thorough in descriptions

BEGIN RECONNAISSANCE NOW. Start by navigating to {target_url} and dismissing any popups."""

        return prompt

    # ── Auth Helpers ─────────────────────────────────────────────

    def _get_auth_session(self, target_url: str) -> Optional[AuthSession]:
        """Get auth session for the target — same pattern as BrowserUseReplayer."""
        if not self.auth_manager:
            return None
        try:
            domain = urllib.parse.urlparse(target_url).netloc
            session = self.auth_manager.authenticate(domain)
            if session and session.success:
                logger.info(f"  🔑 Recon auth: '{session.profile_name}' ({session.auth_type.value})")
                return session
            elif session:
                logger.warning(f"  ⚠️  Recon auth failed for {domain}")
        except Exception as e:
            logger.warning(f"  ⚠️  Recon auth error: {e}")
        return None

    # ── Async Core ───────────────────────────────────────────────

    async def _async_recon(
        self,
        target_url: str,
        max_actions: int = 25,
        focus_areas: Optional[list[str]] = None,
    ) -> ReconResult:
        """Run the recon agent asynchronously."""
        from browser_use import Agent, Browser
        from browser_use.controller import Controller

        start = time.time()
        logger.info(f"🔍 Recon Agent — {target_url}")
        logger.info(f"  Provider: {self.provider} ({self.model}) | Max steps: {max_actions}")

        # ── Site map: mutable state populated by controller actions ──
        site_map: dict = {
            "pages": [],
            "forms": [],
            "api_endpoints": [],
            "auth_flow": {},
            "tech_stack": [],
            "navigation": [],
            "notes": [],
        }

        # ── Controller with recon-specific tools ─────────────────
        controller = Controller()

        @controller.action(
            description=(
                "Document a discovered page/route. Call for EVERY page you visit. "
                "page_type must be one of: login, register, search, admin, profile, "
                "settings, api_docs, content, error"
            )
        )
        def log_page(
            url: str, title: str, description: str, page_type: str = "content"
        ) -> str:
            site_map["pages"].append(
                {
                    "url": url,
                    "title": title,
                    "description": description,
                    "page_type": page_type,
                    "discovered_at": time.time(),
                }
            )
            logger.info(f"  📄 Page: [{page_type}] {title} — {url}")
            return f"Logged page: {title} ({page_type})"

        @controller.action(
            description=(
                "Document a form you found. Include ALL input fields. "
                "fields should be a comma-separated list like: "
                "'email(email,required), password(password,required), remember(checkbox)'"
            )
        )
        def log_form(
            page_url: str,
            form_action: str,
            method: str,
            fields: str,
            submit_button: str = "",
        ) -> str:
            site_map["forms"].append(
                {
                    "page_url": page_url,
                    "action": form_action,
                    "method": method,
                    "fields_raw": fields,
                    "submit_button": submit_button,
                    "discovered_at": time.time(),
                }
            )
            logger.info(f"  📝 Form: {method} {form_action} — {fields[:80]}")
            return f"Logged form: {method} {form_action} with fields: {fields[:100]}"

        @controller.action(
            description=(
                "Document an API endpoint you discovered (from network traffic, "
                "links, page source, or JavaScript). Include the HTTP method and "
                "any known parameters."
            )
        )
        def log_api(
            endpoint: str,
            method: str = "GET",
            description: str = "",
            params: str = "",
        ) -> str:
            site_map["api_endpoints"].append(
                {
                    "endpoint": endpoint,
                    "method": method,
                    "description": description,
                    "params": params,
                    "discovered_at": time.time(),
                }
            )
            logger.info(f"  🔌 API: {method} {endpoint}")
            return f"Logged API: {method} {endpoint}"

        @controller.action(
            description=(
                "Document the authentication flow (how to login, what credentials "
                "are needed). auth_type must be one of: form_login, oauth, api_key, "
                "jwt, cookie, basic"
            )
        )
        def log_auth(
            auth_type: str, login_url: str, fields: str, notes: str = ""
        ) -> str:
            site_map["auth_flow"] = {
                "auth_type": auth_type,
                "login_url": login_url,
                "fields": fields,
                "notes": notes,
            }
            logger.info(f"  🔑 Auth: {auth_type} at {login_url}")
            return f"Logged auth: {auth_type} at {login_url}"

        @controller.action(
            description=(
                "Log a general observation about the application. "
                "category must be one of: general, security, tech_stack, "
                "interesting, navigation"
            )
        )
        def log_note(note: str, category: str = "general") -> str:
            site_map["notes"].append(
                {"note": note, "category": category, "at": time.time()}
            )
            if category == "tech_stack":
                site_map["tech_stack"].append(note)
            logger.info(f"  📌 Note [{category}]: {note[:80]}")
            return f"Noted: {note[:100]}"

        @controller.action(
            description=(
                "Document a navigation menu item or link. "
                "section: main, sidebar, footer, breadcrumb, dropdown"
            )
        )
        def log_nav(text: str, url: str, section: str = "main") -> str:
            site_map["navigation"].append(
                {"text": text, "url": url, "section": section}
            )
            logger.info(f"  🔗 Nav: {text} → {url} ({section})")
            return f"Logged nav: {text} → {url}"

        # ── Auth setup ───────────────────────────────────────────
        auth_session = self._get_auth_session(target_url) if self.auth_manager else None
        storage_state = None
        if auth_session and auth_session.cookies:
            domain = urllib.parse.urlparse(target_url).hostname or "localhost"
            storage_state = {
                "cookies": [
                    {
                        "name": k,
                        "value": v,
                        "domain": domain,
                        "path": "/",
                        "httpOnly": False,
                        "secure": False,
                    }
                    for k, v in auth_session.cookies.items()
                ],
                "origins": [],
            }
            logger.info(
                f"  🔑 Auth: {auth_session.profile_name} ({len(auth_session.cookies)} cookies)"
            )

        # ── Browser setup ────────────────────────────────────────
        chrome_profile = os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ),
            "chrome_profile",
        )
        browser = Browser(
            headless=self.headless,
            disable_security=True,
            storage_state=storage_state,
            executable_path="/usr/bin/google-chrome-stable",
            user_data_dir=chrome_profile,
            args=DEFAULT_CHROME_ARGS + ["--disable-gpu", "--disable-dev-shm-usage"],
        )

        # ── Build prompt and create agent ────────────────────────
        task = self._build_recon_prompt(target_url, focus_areas)
        agent = Agent(
            task=task,
            llm=self._create_llm(),
            browser=browser,
            controller=controller,
            max_actions_per_step=5,
        )

        try:
            # Run the recon agent
            logger.info(f"  ▶️  Running recon agent (max {max_actions} steps)...")
            history = await agent.run(max_steps=max_actions)
            logger.info(
                f"  ✅ Recon done — {len(site_map['pages'])} pages, "
                f"{len(site_map['forms'])} forms, "
                f"{len(site_map['api_endpoints'])} APIs"
            )

            # Supplement with DOM element extraction on the final page
            try:
                page = await browser.get_current_page()
                if page:
                    elements = await page.evaluate(EXTRACT_ELEMENTS_JS)
                    if elements:
                        current_url = page.url
                        self.site_cache.cache_page(page, target_url, current_url)
            except Exception:
                pass

            # Save screenshots from the agent's history
            screenshots: list[str] = []
            try:
                for i, data in enumerate(history.screenshots() or []):
                    p = (
                        Path(self.site_cache.cache_dir)
                        / f"recon_{int(time.time())}_{i}.png"
                    )
                    p.write_bytes(data)
                    screenshots.append(str(p))
                if screenshots:
                    logger.info(f"  🎬 Saved {len(screenshots)} recon screenshots")
            except Exception:
                pass

            # Build result
            duration = time.time() - start
            result = ReconResult(
                target_url=target_url,
                site_map=site_map,
                screenshots=screenshots,
                duration=duration,
                actions_taken=max_actions,
            )

            # Persist to SiteCache
            result.save_to_cache(self.site_cache, target_url)
            logger.info(f"  💾 Saved to SiteCache")

            # Also save JSON for inspection
            try:
                json_path = result.save_json()
                logger.info(f"  💾 Saved JSON: {json_path}")
            except Exception:
                pass

            logger.info(f"  📋 {result.summary()}")
            return result

        except Exception as e:
            logger.error(f"  ❌ Recon error: {e}")
            return ReconResult(
                target_url=target_url,
                site_map=site_map,
                screenshots=[],
                duration=time.time() - start,
                actions_taken=0,
                error=str(e),
            )
        finally:
            try:
                await browser.stop()
            except Exception:
                pass

    # ── Public Sync API ──────────────────────────────────────────

    @staticmethod
    def _run_async(coro):
        """Run an async coroutine from sync context, handling nested loops."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return asyncio.run(coro)

    def recon(
        self,
        target_url: str,
        max_actions: int = 25,
        focus_areas: Optional[list[str]] = None,
    ) -> ReconResult:
        """
        Run reconnaissance on a target website.

        Args:
            target_url: The target URL to explore (e.g., "http://localhost:3333")
            max_actions: Maximum number of agent steps (default 25)
            focus_areas: Optional list of areas to emphasize
                        (e.g., ["forms", "api_endpoints", "auth_flow"])

        Returns:
            ReconResult with structured site knowledge
        """
        return self._run_async(
            self._async_recon(target_url, max_actions, focus_areas)
        )
