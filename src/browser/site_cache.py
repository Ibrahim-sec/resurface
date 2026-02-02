"""
Site Knowledge Cache — caches UI structure, routes, and API endpoints per target.

After the first vision replay against a target, the cache stores:
- Page routes and their interactive elements (with CSS selectors)
- Discovered API endpoints
- Navigation map (vuln_type → relevant route)

Subsequent replays against the same target can:
- Skip exploration and go straight to the relevant page
- Use cached CSS selectors for form-filling (no LLM needed)
- Know the API endpoints without interceptor discovery
"""

import json
import hashlib
import time
from pathlib import Path
from datetime import datetime
from typing import Optional
from loguru import logger


# JavaScript to extract interactive elements from a page
EXTRACT_ELEMENTS_JS = """
(() => {
    const elements = [];
    const selectors = 'input, button, a[href], select, textarea, ' +
        '[role="button"], [role="link"], [role="textbox"], [role="combobox"], ' +
        'mat-select, [routerlink]';

    document.querySelectorAll(selectors).forEach(el => {
        const rect = el.getBoundingClientRect();
        // Skip hidden/zero-size elements
        if (rect.width === 0 || rect.height === 0) return;
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') return;

        // Build best CSS selector
        let selector = null;
        if (el.id) {
            selector = '#' + CSS.escape(el.id);
        } else if (el.getAttribute('data-testid')) {
            selector = '[data-testid="' + el.getAttribute('data-testid') + '"]';
        } else if (el.getAttribute('name')) {
            selector = el.tagName.toLowerCase() + '[name="' + el.getAttribute('name') + '"]';
        } else if (el.getAttribute('aria-label')) {
            selector = '[aria-label="' + el.getAttribute('aria-label') + '"]';
        } else if (el.placeholder) {
            selector = el.tagName.toLowerCase() + '[placeholder="' + el.placeholder + '"]';
        }

        // Get label text
        let label = '';
        if (el.id) {
            const labelEl = document.querySelector('label[for="' + el.id + '"]');
            if (labelEl) label = labelEl.textContent.trim();
        }
        if (!label && el.getAttribute('aria-label')) {
            label = el.getAttribute('aria-label');
        }
        if (!label && el.placeholder) {
            label = el.placeholder;
        }

        elements.push({
            tag: el.tagName.toLowerCase(),
            type: el.type || null,
            id: el.id || null,
            name: el.getAttribute('name') || null,
            text: el.textContent.trim().slice(0, 80),
            placeholder: el.placeholder || null,
            label: label || null,
            href: el.getAttribute('href') || el.getAttribute('routerlink') || null,
            selector: selector,
            role: el.getAttribute('role') || null
        });
    });
    return elements;
})()
"""

# JavaScript to discover all internal links/routes
EXTRACT_ROUTES_JS = """
(() => {
    const routes = [];
    document.querySelectorAll('a[href], [routerlink]').forEach(el => {
        const href = el.getAttribute('href') || el.getAttribute('routerlink') || '';
        const text = el.textContent.trim().slice(0, 80);
        if (!text || !href) return;
        // Only internal links
        try {
            const url = new URL(href, window.location.origin);
            if (url.host === window.location.host) {
                const route = url.hash || url.pathname;
                routes.push({route: route, text: text, full_url: url.href});
            }
        } catch(e) {
            // Relative hash routes like #/login
            if (href.startsWith('#') || href.startsWith('/')) {
                routes.push({route: href, text: text, full_url: href});
            }
        }
    });
    // Deduplicate by route
    const seen = new Set();
    return routes.filter(r => {
        if (seen.has(r.route)) return false;
        seen.add(r.route);
        return true;
    });
})()
"""


# Vuln type → keywords for matching relevant pages
VULN_ROUTE_KEYWORDS = {
    "xss": ["search", "comment", "feedback", "contact", "post", "message", "input"],
    "sqli": ["login", "signin", "sign-in", "auth", "search", "user"],
    "privilege_escalation": ["register", "signup", "sign-up", "registration", "account", "profile"],
    "idor": ["profile", "account", "user", "order", "basket", "cart", "admin"],
    "info_disclosure": ["admin", "config", "debug", "api", "ftp", "backup"],
    "broken_access_control": ["admin", "dashboard", "management", "panel"],
    "path_traversal": ["file", "download", "ftp", "upload", "image"],
    "open_redirect": ["login", "redirect", "return", "next", "url"],
    "csrf": ["profile", "settings", "account", "password", "email"],
}


class SiteCache:
    """
    Manages per-target site knowledge caching.

    Cache structure:
    {
        "target": "http://localhost:3333",
        "updated_at": "2026-02-01T18:00:00",
        "routes": {
            "/#/login": {
                "text": "Login",
                "elements": [...],
                "cached_at": "2026-02-01T18:00:00"
            }
        },
        "api_endpoints": {
            "POST /api/Users/": {
                "description": "user registration",
                "request_body_keys": ["email", "password", ...],
                "discovered_from": "/#/register"
            }
        }
    }
    """

    def __init__(self, cache_dir: str = "data/site_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, target_url: str) -> Path:
        """Generate cache filename from target URL."""
        # Normalize: strip protocol, replace special chars
        clean = target_url.replace("http://", "").replace("https://", "")
        clean = clean.rstrip("/").replace(":", "_").replace("/", "_")
        return self.cache_dir / f"{clean}.json"

    def load(self, target_url: str) -> Optional[dict]:
        """Load existing cache for a target. Returns None if no cache."""
        path = self._cache_path(target_url)
        if not path.exists():
            return None
        try:
            with open(path) as f:
                data = json.load(f)
            logger.info(f"  📦 Site cache loaded: {path.name} "
                        f"({len(data.get('routes', {}))} routes, "
                        f"{len(data.get('api_endpoints', {}))} endpoints)")
            return data
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"  ⚠️ Failed to load site cache: {e}")
            return None

    def save(self, target_url: str, data: dict):
        """Save cache data for a target."""
        data["target"] = target_url
        data["updated_at"] = datetime.now().isoformat()
        path = self._cache_path(target_url)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.debug(f"  💾 Site cache saved: {path.name}")

    def _ensure_data(self, target_url: str) -> dict:
        """Load existing cache or create empty structure."""
        data = self.load(target_url)
        if data is None:
            data = {
                "target": target_url,
                "updated_at": datetime.now().isoformat(),
                "routes": {},
                "api_endpoints": {},
            }
        return data

    # ── Extraction ──

    def extract_elements(self, page) -> list:
        """Extract interactive elements from the current page via DOM inspection."""
        try:
            elements = page.evaluate(EXTRACT_ELEMENTS_JS)
            return elements or []
        except Exception as e:
            logger.debug(f"  Element extraction failed: {e}")
            return []

    def extract_routes(self, page) -> list:
        """Extract all internal routes/links from the current page."""
        try:
            routes = page.evaluate(EXTRACT_ROUTES_JS)
            return routes or []
        except Exception as e:
            logger.debug(f"  Route extraction failed: {e}")
            return []

    # ── Caching ──

    def cache_page(self, page, target_url: str, route: str = None):
        """Extract and cache elements for the current page."""
        if route is None:
            # Derive route from current URL
            current_url = page.url
            base = target_url.rstrip("/")
            if current_url.startswith(base):
                route = current_url[len(base):] or "/"
            else:
                route = current_url

        elements = self.extract_elements(page)
        if not elements:
            return

        data = self._ensure_data(target_url)
        data["routes"][route] = {
            "text": route,
            "elements": elements,
            "element_count": len(elements),
            "cached_at": datetime.now().isoformat(),
        }
        self.save(target_url, data)
        logger.info(f"  📦 Cached page: {route} ({len(elements)} elements)")

    def cache_routes_from_page(self, page, target_url: str):
        """Discover and cache all routes visible on the current page."""
        routes = self.extract_routes(page)
        if not routes:
            return

        data = self._ensure_data(target_url)
        for r in routes:
            route_key = r["route"]
            if route_key not in data["routes"]:
                data["routes"][route_key] = {
                    "text": r["text"],
                    "elements": None,  # Not yet inspected
                    "cached_at": datetime.now().isoformat(),
                }
        self.save(target_url, data)
        logger.info(f"  📦 Cached {len(routes)} route links from current page")

    def cache_api_endpoint(self, target_url: str, method: str, url: str,
                           description: str = "", body_keys: list = None,
                           discovered_from: str = None):
        """Cache a discovered API endpoint."""
        data = self._ensure_data(target_url)
        key = f"{method.upper()} {url}"
        data["api_endpoints"][key] = {
            "description": description,
            "request_body_keys": body_keys or [],
            "discovered_from": discovered_from or "",
            "cached_at": datetime.now().isoformat(),
        }
        self.save(target_url, data)
        logger.info(f"  📦 Cached API endpoint: {key}")

    # ── Retrieval ──

    def get_relevant_route(self, target_url: str, vuln_type: str) -> Optional[str]:
        """Find the most relevant cached route for a vulnerability type."""
        data = self.load(target_url)
        if not data or not data.get("routes"):
            return None

        keywords = VULN_ROUTE_KEYWORDS.get(vuln_type, [])
        if not keywords:
            return None

        best_route = None
        best_score = 0

        for route, info in data["routes"].items():
            route_lower = route.lower()
            text_lower = (info.get("text") or "").lower()
            score = 0
            for kw in keywords:
                if kw in route_lower:
                    score += 2  # Route match is stronger
                if kw in text_lower:
                    score += 1
            if score > best_score:
                best_score = score
                best_route = route

        return best_route

    def get_page_elements(self, target_url: str, route: str) -> Optional[list]:
        """Get cached elements for a specific route."""
        data = self.load(target_url)
        if not data:
            return None
        route_data = data.get("routes", {}).get(route)
        if route_data and route_data.get("elements"):
            return route_data["elements"]
        return None

    def get_api_endpoints(self, target_url: str) -> dict:
        """Get all cached API endpoints for a target."""
        data = self.load(target_url)
        if not data:
            return {}
        return data.get("api_endpoints", {})

    def get_form_elements(self, target_url: str, route: str) -> list:
        """Get only form-fillable elements (inputs, selects, textareas) for a route."""
        elements = self.get_page_elements(target_url, route)
        if not elements:
            return []
        form_tags = {"input", "select", "textarea", "mat-select"}
        return [
            e for e in elements
            if e.get("tag") in form_tags and e.get("selector")
        ]

    def get_buttons(self, target_url: str, route: str) -> list:
        """Get clickable buttons for a route."""
        elements = self.get_page_elements(target_url, route)
        if not elements:
            return []
        return [
            e for e in elements
            if e.get("tag") == "button" or e.get("role") == "button"
        ]

    # ── Prompt Context Generation ──

    def get_prompt_context(self, target_url: str, vuln_type: str = None) -> str:
        """
        Generate a prompt context block from cached site knowledge.
        This gets injected into the vision agent's prompt so it can
        skip exploration and go straight to exploitation.
        """
        data = self.load(target_url)
        if not data:
            return ""

        lines = []
        lines.append("## 🗺️ Known Application Structure (from previous scans)")
        lines.append("Use this knowledge to skip exploration and go straight to the right page.\n")

        # Routes
        routes = data.get("routes", {})
        if routes:
            lines.append("**Known pages:**")
            for route, info in routes.items():
                text = info.get("text", "")
                el_count = info.get("element_count", 0)
                if el_count:
                    lines.append(f"- `{route}` — {text} ({el_count} interactive elements)")
                else:
                    lines.append(f"- `{route}` — {text}")

        # API endpoints
        endpoints = data.get("api_endpoints", {})
        if endpoints:
            lines.append("\n**Known API endpoints:**")
            for endpoint, info in endpoints.items():
                desc = info.get("description", "")
                lines.append(f"- `{endpoint}` — {desc}")

        # Relevant page for this vuln type
        if vuln_type:
            relevant = self.get_relevant_route(target_url, vuln_type)
            if relevant:
                lines.append(f"\n**⚡ Recommended page for {vuln_type}:** `{relevant}`")
                lines.append(f"Navigate directly: use \"navigate\" action to go to this route.")

                # Show form elements if cached
                form_els = self.get_form_elements(target_url, relevant)
                if form_els:
                    lines.append(f"\n**Form elements on `{relevant}`:**")
                    for el in form_els:
                        tag = el.get("tag", "?")
                        label = el.get("label") or el.get("placeholder") or el.get("id") or "?"
                        sel = el.get("selector", "?")
                        lines.append(f"- {tag}: \"{label}\" → selector: `{sel}`")

                    lines.append("\n**💡 FAST PATH:** You can fill this form using \"console\" with "
                                 "Playwright-compatible selectors instead of clicking:")
                    lines.append("```")
                    for el in form_els:
                        sel = el.get("selector")
                        tag = el.get("tag")
                        label = el.get("label") or el.get("placeholder") or ""
                        if sel and tag in ("input", "textarea"):
                            lines.append(
                                f"document.querySelector('{sel}').value = '<value>';")
                            lines.append(
                                f"document.querySelector('{sel}')"
                                f".dispatchEvent(new Event('input', {{bubbles:true}}));")
                    lines.append("```")

                # Show relevant API endpoint
                if endpoints:
                    for ep, info in endpoints.items():
                        if any(kw in ep.lower() for kw in
                               VULN_ROUTE_KEYWORDS.get(vuln_type, [])):
                            lines.append(f"\n**🎯 Direct exploit:** Use \"fetch\" to call `{ep}` "
                                         f"with the malicious payload — no form needed!")
                            break

        return "\n".join(lines)

    # ── Fast Path: Programmatic Form Fill ──

    def fill_form(self, page, target_url: str, route: str,
                  field_values: dict) -> bool:
        """
        Fill a cached form programmatically using CSS selectors.
        No LLM needed — direct Playwright interaction.

        Args:
            page: Playwright page object
            target_url: Target base URL
            route: Page route (e.g., '/#/register')
            field_values: Dict mapping label/placeholder → value
                         e.g. {"Email": "test@example.com", "Password": "pass123"}

        Returns:
            True if at least one field was filled.
        """
        form_els = self.get_form_elements(target_url, route)
        if not form_els:
            logger.debug(f"  No cached form elements for {route}")
            return False

        filled = 0
        for el in form_els:
            selector = el.get("selector")
            if not selector:
                continue

            # Match by label, placeholder, id, or name
            el_label = (el.get("label") or "").lower()
            el_placeholder = (el.get("placeholder") or "").lower()
            el_id = (el.get("id") or "").lower()
            el_name = (el.get("name") or "").lower()

            for field_key, value in field_values.items():
                key_lower = field_key.lower()
                if (key_lower in el_label or key_lower in el_placeholder or
                        key_lower in el_id or key_lower in el_name):
                    try:
                        tag = el.get("tag", "")
                        if tag in ("input", "textarea"):
                            page.fill(selector, value)
                            filled += 1
                            logger.info(f"  ⚡ Fast-fill: {selector} = '{value[:30]}...'")
                        elif tag in ("select", "mat-select"):
                            page.select_option(selector, value)
                            filled += 1
                            logger.info(f"  ⚡ Fast-select: {selector} = '{value}'")
                    except Exception as e:
                        logger.debug(f"  Fast-fill failed for {selector}: {e}")
                    break

        return filled > 0

    def click_button(self, page, target_url: str, route: str,
                     button_text: str = None) -> bool:
        """
        Click a cached button by text match.

        Args:
            page: Playwright page
            target_url: Target base URL
            route: Page route
            button_text: Text to match (e.g., "Register", "Login"). If None, clicks first button.

        Returns:
            True if button was clicked.
        """
        buttons = self.get_buttons(target_url, route)
        if not buttons:
            return False

        target_btn = None
        if button_text:
            text_lower = button_text.lower()
            for btn in buttons:
                btn_text = (btn.get("text") or "").lower()
                if text_lower in btn_text:
                    target_btn = btn
                    break

        if not target_btn and buttons:
            target_btn = buttons[0]

        if target_btn and target_btn.get("selector"):
            try:
                page.click(target_btn["selector"])
                logger.info(f"  ⚡ Fast-click: {target_btn['selector']} "
                            f"('{target_btn.get('text', '')[:30]}')")
                return True
            except Exception as e:
                logger.debug(f"  Fast-click failed: {e}")

        return False

    # ── Crawl/Inspect ──

    def crawl(self, page, target_url: str, routes_to_visit: list = None):
        """
        Crawl a target and cache all discovered pages and elements.

        This is the 'inspect' command — does a one-time deep scan of the app.

        Args:
            page: Playwright page (already navigated to target)
            target_url: Base URL of the target
            routes_to_visit: Specific routes to visit. If None, discovers from main page.
        """
        base = target_url.rstrip("/")
        data = self._ensure_data(target_url)

        # First, cache the current page (home)
        home_elements = self.extract_elements(page)
        home_route = page.url.replace(base, "") or "/"
        data["routes"][home_route] = {
            "text": "Home",
            "elements": home_elements,
            "element_count": len(home_elements),
            "cached_at": datetime.now().isoformat(),
        }
        logger.info(f"  📦 Inspected: {home_route} ({len(home_elements)} elements)")

        # Discover routes from main page
        discovered = self.extract_routes(page)
        if routes_to_visit is None:
            routes_to_visit = [r["route"] for r in discovered]

        # Store route texts
        route_texts = {r["route"]: r["text"] for r in discovered}

        # Visit each route and extract elements
        for route in routes_to_visit:
            if route == home_route:
                continue

            # Build full URL
            if route.startswith("http"):
                full_url = route
            elif route.startswith("#") or route.startswith("/#"):
                full_url = f"{base}/{route.lstrip('/')}"
            else:
                full_url = f"{base}{route}"

            try:
                page.goto(full_url, timeout=10000, wait_until="domcontentloaded")
                page.wait_for_timeout(1000)  # Let page settle

                elements = self.extract_elements(page)
                data["routes"][route] = {
                    "text": route_texts.get(route, route),
                    "elements": elements,
                    "element_count": len(elements),
                    "cached_at": datetime.now().isoformat(),
                }
                logger.info(f"  📦 Inspected: {route} ({len(elements)} elements)")

            except Exception as e:
                logger.debug(f"  Failed to inspect {route}: {e}")
                data["routes"][route] = {
                    "text": route_texts.get(route, route),
                    "elements": None,
                    "error": str(e),
                    "cached_at": datetime.now().isoformat(),
                }

        self.save(target_url, data)
        total_routes = len([r for r in data["routes"].values() if r.get("elements")])
        total_elements = sum(
            len(r.get("elements") or []) for r in data["routes"].values()
        )
        logger.info(
            f"  ✅ Site inspection complete: {total_routes} pages, "
            f"{total_elements} total elements"
        )
        return data
