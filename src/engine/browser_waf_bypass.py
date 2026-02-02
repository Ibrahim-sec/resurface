"""
Browser WAF Bypass Integration

Wraps the existing MutationEngine for use in browser-use async context.
Bridges the sync MutationEngine API with async browser-use tools by using
asyncio.to_thread() for the blocking adaptive_mutate loop and direct calls
for lightweight variant generation.

Usage in browser-use replay:
    waf_bypass = BrowserWAFBypass(api_key=..., verbose=True)
    create_waf_bypass_tools(controller, waf_bypass, browser, target_url, vuln_type)
"""
import asyncio
import json
import time
from typing import Optional
from urllib.parse import urlparse, urlencode, urljoin

import httpx
from loguru import logger

from src.engine.mutation_engine import MutationEngine
from src.models import MutationAttempt, MutationResult


class BrowserWAFBypass:
    """Wraps MutationEngine for use in browser-use async context.

    The key challenge: MutationEngine.adaptive_mutate() expects a sync replay_fn,
    but browser-use tools are async. This wrapper bridges that gap by running the
    sync mutation loop inside a thread via asyncio.to_thread().
    """

    def __init__(
        self,
        api_key: str,
        model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
        provider: str = "groq",
        verbose: bool = False,
        max_attempts: int = 5,
        variants_per_round: int = 3,
        temperature: float = 0.4,
    ):
        self.engine = MutationEngine(
            api_key=api_key,
            model=model,
            provider=provider,
            max_mutation_attempts=max_attempts,
            variants_per_round=variants_per_round,
            temperature=temperature,
            verbose=verbose,
        )
        self.verbose = verbose
        self.bypass_history: list[dict] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _extract_cookies_from_browser(browser) -> dict[str, str]:
        """Try to extract cookies from a browser-use browser context.

        Supports the browser-use Browser wrapper (browser.context → Playwright
        BrowserContext) as well as a raw Playwright BrowserContext.
        Returns a plain dict of cookie name→value.
        """
        cookies: dict[str, str] = {}
        try:
            ctx = getattr(browser, "context", None) or browser
            # browser-use may wrap the real context one level deeper
            if hasattr(ctx, "browser_context"):
                ctx = ctx.browser_context
            if ctx is not None and hasattr(ctx, "cookies"):
                raw = await ctx.cookies()
                for c in raw:
                    cookies[c["name"]] = c["value"]
        except Exception as exc:
            logger.debug(f"Could not extract browser cookies: {exc}")
        return cookies

    def _build_request_summary(
        self, url: str, method: str, headers: dict, body: dict
    ) -> str:
        """Build a human-readable request summary for the LLM context."""
        parts = [f"{method.upper()} {url}"]
        for k, v in (headers or {}).items():
            parts.append(f"{k}: {v}")
        if body:
            parts.append("")
            parts.append(json.dumps(body, ensure_ascii=False)[:2000])
        return "\n".join(parts)

    @staticmethod
    def _inject_payload(
        url: str,
        method: str,
        headers: dict,
        body: dict,
        original_payload: str,
        new_payload: str,
    ) -> tuple[str, dict, dict]:
        """Replace *original_payload* with *new_payload* in url / headers / body.

        Returns (new_url, new_headers, new_body).
        """
        new_url = url.replace(original_payload, new_payload) if original_payload in url else url

        new_headers = {}
        for k, v in (headers or {}).items():
            new_headers[k] = v.replace(original_payload, new_payload) if isinstance(v, str) else v

        new_body: dict = {}
        for k, v in (body or {}).items():
            if isinstance(v, str) and original_payload in v:
                new_body[k] = v.replace(original_payload, new_payload)
            else:
                new_body[k] = v

        return new_url, new_headers, new_body

    # ------------------------------------------------------------------
    # Public API — async
    # ------------------------------------------------------------------

    async def check_and_bypass(
        self,
        payload: str,
        vuln_type: str,
        url: str,
        method: str = "GET",
        headers: Optional[dict] = None,
        body: Optional[dict] = None,
        status_code: Optional[int] = None,
        response_body: str = "",
        response_headers: str = "",
        browser=None,
        target_url: str = "",
    ) -> dict:
        """Check if a payload was blocked and, if so, generate + test bypass variants.

        Uses httpx (async, run inside a thread for the sync MutationEngine loop)
        to test each variant. Optionally pulls cookies from the browser context
        so that authenticated sessions carry over.

        Returns a dict::

            {
                "blocked": bool,
                "bypass_found": bool,
                "original_payload": str,
                "bypass_payload": str | None,
                "strategy": str,
                "attempts": int,
                "details": list[dict],
            }
        """
        headers = headers or {}
        body = body or {}

        result: dict = {
            "blocked": False,
            "bypass_found": False,
            "original_payload": payload,
            "bypass_payload": None,
            "strategy": "",
            "attempts": 0,
            "details": [],
        }

        # 1. Quick heuristic check
        blocked = MutationEngine.heuristic_block_detected(
            payload, status_code, response_body, response_headers
        )
        if not blocked:
            logger.debug("Heuristic says payload was NOT blocked — skipping mutation.")
            self.bypass_history.append(result)
            return result

        result["blocked"] = True
        logger.info(
            f"🛡️ Payload appears blocked (status={status_code}). "
            f"Starting browser WAF bypass for: {payload[:60]}…"
        )

        # 2. Grab browser cookies (if available)
        browser_cookies: dict[str, str] = {}
        if browser is not None:
            browser_cookies = await self._extract_cookies_from_browser(browser)
            if browser_cookies and self.verbose:
                logger.debug(f"Extracted {len(browser_cookies)} cookie(s) from browser context")

        # 3. Build context strings
        request_summary = self._build_request_summary(url, method, headers, body)

        # 4. Create a *sync* replay_fn that uses httpx in a new event loop
        #    (adaptive_mutate is sync — it will call this from the thread)
        original_payload = payload

        def _sync_replay(mutated_payload: str) -> tuple[Optional[int], str]:
            """Sync replay function suitable for MutationEngine.adaptive_mutate().

            Runs a fresh httpx request synchronously (called from a worker thread
            via asyncio.to_thread, so blocking is fine).
            """
            req_url, req_headers, req_body = BrowserWAFBypass._inject_payload(
                url, method, headers, body, original_payload, mutated_payload,
            )

            # Merge browser cookies into the Cookie header
            if browser_cookies:
                cookie_header = "; ".join(f"{k}={v}" for k, v in browser_cookies.items())
                existing = req_headers.get("Cookie", "")
                if existing:
                    cookie_header = f"{existing}; {cookie_header}"
                req_headers["Cookie"] = cookie_header

            try:
                with httpx.Client(timeout=30, follow_redirects=True, verify=False) as client:
                    if method.upper() in ("POST", "PUT", "PATCH"):
                        content_type = req_headers.get("Content-Type", "")
                        if "json" in content_type:
                            resp = client.request(
                                method.upper(), req_url,
                                headers=req_headers,
                                json=req_body,
                            )
                        else:
                            resp = client.request(
                                method.upper(), req_url,
                                headers=req_headers,
                                data=req_body,
                            )
                    else:
                        resp = client.request(
                            method.upper(), req_url,
                            headers=req_headers,
                        )
                    return resp.status_code, resp.text[:5000]
            except Exception as exc:
                logger.warning(f"Sync replay error: {exc}")
                return None, str(exc)

        # 5. Run the blocking adaptive_mutate in a thread
        mutation_result: MutationResult = await asyncio.to_thread(
            self.engine.adaptive_mutate,
            original_payload,
            vuln_type,
            request_summary,
            status_code,
            response_body,
            _sync_replay,
        )

        # 6. Build result dict
        result["attempts"] = mutation_result.total_attempts
        result["details"] = [
            {
                "attempt": a.attempt_number,
                "payload": a.mutated_payload,
                "strategy": a.strategy,
                "rationale": a.rationale,
                "status_code": a.status_code,
                "blocked": a.blocked,
                "success": a.success,
                "response_snippet": a.response_snippet[:500],
            }
            for a in mutation_result.attempts
        ]

        if mutation_result.bypassed and mutation_result.final_payload:
            result["bypass_found"] = True
            result["bypass_payload"] = mutation_result.final_payload
            # Find the winning strategy
            for a in mutation_result.attempts:
                if a.mutated_payload == mutation_result.final_payload:
                    result["strategy"] = a.strategy
                    break
            logger.info(
                f"✅ WAF bypass found! Strategy={result['strategy']}  "
                f"Payload: {result['bypass_payload'][:80]}…"
            )
        else:
            logger.info(
                f"❌ No bypass found after {mutation_result.total_attempts} attempt(s)."
            )

        self.bypass_history.append(result)
        return result

    async def mutate_payload(
        self,
        payload: str,
        vuln_type: str,
        context: str = "",
    ) -> list[dict]:
        """Generate mutation variants *without* testing them.

        Useful when the browser-use agent wants to receive candidate payloads and
        inject them manually through the browser DOM.

        Returns a list of::

            {"payload": str, "strategy": str, "rationale": str}
        """
        request_summary = context or "(browser-based — no HTTP request summary available)"

        # _generate_variants is sync but fast (single LLM call) — run in a thread
        # to avoid blocking the event loop.
        variants: list[dict] = await asyncio.to_thread(
            self.engine._generate_variants,
            payload,                # original_payload
            vuln_type,              # vuln_type
            request_summary,        # request_summary
            None,                   # status_code (unknown in browser context)
            "Payload was blocked or stripped by a WAF / input filter.",
            [],                     # previous_attempts
        )

        # Normalise keys — _generate_variants returns dicts with
        # payload / strategy / rationale but guard against missing keys.
        normalised: list[dict] = []
        for v in variants:
            normalised.append({
                "payload": v.get("payload", ""),
                "strategy": v.get("strategy", "unknown"),
                "rationale": v.get("rationale", ""),
            })
        return normalised

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_bypass_summary(self) -> str:
        """Human-readable summary of all bypass attempts in this session."""
        if not self.bypass_history:
            return "No WAF bypass attempts recorded in this session."

        lines: list[str] = [
            f"## WAF Bypass Summary — {len(self.bypass_history)} attempt(s)\n"
        ]
        total_blocked = sum(1 for r in self.bypass_history if r["blocked"])
        total_bypassed = sum(1 for r in self.bypass_history if r["bypass_found"])
        lines.append(
            f"Blocked: {total_blocked} | Bypassed: {total_bypassed} | "
            f"No block: {len(self.bypass_history) - total_blocked}\n"
        )

        for i, entry in enumerate(self.bypass_history, 1):
            if not entry["blocked"]:
                lines.append(
                    f"  {i}. `{entry['original_payload'][:60]}…` — **not blocked**"
                )
                continue

            status = "✅ BYPASSED" if entry["bypass_found"] else "❌ no bypass"
            lines.append(
                f"  {i}. `{entry['original_payload'][:60]}…` — {status} "
                f"({entry['attempts']} attempt(s))"
            )
            if entry["bypass_found"]:
                lines.append(
                    f"     → Bypass: `{entry['bypass_payload'][:80]}…` "
                    f"[{entry['strategy']}]"
                )

        return "\n".join(lines)


# ======================================================================
# Browser-use Controller tool registration
# ======================================================================

def create_waf_bypass_tools(
    controller,
    waf_bypass: BrowserWAFBypass,
    browser,
    target_url: str,
    vuln_type: str,
):
    """Register WAF bypass actions on a browser-use Controller.

    Call this inside ``_async_replay`` after creating the controller and
    before launching the browser-use Agent loop.

    Registers two tools:

    1. **mutate_payload** — generate 3-5 bypass variants for a blocked payload.
    2. **test_bypass** — fire an HTTP request with a specific bypass payload and
       report whether it was blocked.
    """

    @controller.action(
        description=(
            "Generate WAF/filter bypass variants for a blocked payload. "
            "Use when your payload was stripped, escaped, or returned 403. "
            "Returns bypass variants with different encoding, tag alternatives, "
            "case tricks, and evasion strategies. Try each variant."
        )
    )
    async def mutate_payload(payload: str, context: str = "") -> str:  # noqa: F811
        """Ask the LLM mutation engine for bypass ideas."""
        variants = await waf_bypass.mutate_payload(payload, vuln_type, context)
        if not variants:
            return "No variants generated. Try a completely different approach."

        result = f"## {len(variants)} Bypass Variants\n"
        for idx, v in enumerate(variants, 1):
            result += (
                f"\n{idx}. **{v['strategy']}**: `{v['payload']}`\n"
                f"   Rationale: {v['rationale']}\n"
            )
        result += (
            "\nTry each variant in order. "
            "Use test_bypass to verify via HTTP, or type them directly into browser forms."
        )
        return result

    @controller.action(
        description=(
            "Test a bypass payload via HTTP request. Use after mutate_payload "
            "gives you variants. Tests if the variant gets past the WAF/filter. "
            "Returns a clear blocked / not-blocked verdict."
        )
    )
    async def test_bypass(
        payload: str,
        url: str = "",
        method: str = "GET",
        headers: Optional[dict] = None,
        body: Optional[dict] = None,
    ) -> str:
        """Fire a single HTTP request with the payload and report back."""
        request_url = url or target_url
        if not request_url:
            return "Error: no URL provided and no default target_url configured."

        req_headers = dict(headers) if headers else {}
        req_body = dict(body) if body else {}

        # Pull cookies from the browser context for authenticated testing
        browser_cookies = await BrowserWAFBypass._extract_cookies_from_browser(browser)
        if browser_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in browser_cookies.items())
            existing = req_headers.get("Cookie", "")
            if existing:
                cookie_str = f"{existing}; {cookie_str}"
            req_headers["Cookie"] = cookie_str

        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False
            ) as client:
                if method.upper() in ("POST", "PUT", "PATCH"):
                    content_type = req_headers.get("Content-Type", "")
                    if "json" in content_type:
                        resp = await client.request(
                            method.upper(), request_url,
                            headers=req_headers, json=req_body,
                        )
                    else:
                        resp = await client.request(
                            method.upper(), request_url,
                            headers=req_headers, data=req_body,
                        )
                else:
                    resp = await client.request(
                        method.upper(), request_url,
                        headers=req_headers,
                    )
        except Exception as exc:
            return f"❌ Request failed: {exc}"

        status = resp.status_code
        resp_body = resp.text[:3000]
        resp_headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

        blocked = MutationEngine.heuristic_block_detected(
            payload, status, resp_body, resp_headers_str
        )

        if blocked:
            verdict = (
                f"❌ **BLOCKED** (HTTP {status})\n"
                f"The payload `{payload[:80]}` was blocked/filtered.\n"
                f"Response snippet:\n```\n{resp_body[:500]}\n```\n"
                "Try the next variant from mutate_payload, or request new variants."
            )
        else:
            verdict = (
                f"✅ **NOT BLOCKED** (HTTP {status})\n"
                f"The payload `{payload[:80]}` appears to have passed the WAF/filter!\n"
                f"Response snippet:\n```\n{resp_body[:500]}\n```\n"
                "Use this payload in the browser to confirm the vulnerability triggers."
            )

            # Record the successful bypass in history
            waf_bypass.bypass_history.append({
                "blocked": True,
                "bypass_found": True,
                "original_payload": "(tested via test_bypass tool)",
                "bypass_payload": payload,
                "strategy": "manual_test",
                "attempts": 1,
                "details": [{
                    "attempt": 1,
                    "payload": payload,
                    "strategy": "manual_test",
                    "rationale": "Directly tested via test_bypass browser tool",
                    "status_code": status,
                    "blocked": False,
                    "success": True,
                    "response_snippet": resp_body[:500],
                }],
            })

        return verdict
