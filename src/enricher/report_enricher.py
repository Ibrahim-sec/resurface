"""
Report Enricher — LLM-powered pre-processing that turns raw parsed reports
into battle-ready attack plans before the browser agent touches anything.

Pipeline:  Raw Report → Parser → Enricher → Browser Agent
                                    ↓
                              1. Pre-flight recon (is the target alive? endpoint exists?)
                              2. Enrichment (fill gaps, generate payloads, infer URLs)
                              3. Multi-strategy generation (3 attack plans, ranked)
                              4. Post-failure refinement (learn from failed attempts)
"""
import json
import httpx
from typing import Optional
from dataclasses import dataclass, field
from loguru import logger

from src.models import ParsedReport, PoC_Step, VulnType
from src.llm import LLMClient


# ── Data Models ──────────────────────────────────────────────────────

@dataclass
class AttackStrategy:
    """A single attack plan the agent can follow."""
    name: str                           # e.g. "Direct API exploit", "Browser form fill"
    description: str                    # What this strategy does
    steps: list[dict] = field(default_factory=list)  # Enriched step dicts
    payloads: list[str] = field(default_factory=list)  # Payload variants to try
    fallback_note: str = ""             # What to do if this strategy fails
    priority: int = 1                   # 1 = try first, 2 = backup, 3 = last resort


@dataclass
class PreflightResult:
    """Results from pre-flight target reconnaissance."""
    target_alive: bool = False
    status_code: int = 0
    endpoint_exists: bool = False       # Does the specific vuln endpoint respond?
    endpoint_status: int = 0
    redirect_url: str = ""              # If endpoint redirects
    auth_required: bool = False         # Got 401/403?
    notes: str = ""


@dataclass
class EnrichedReport:
    """A parsed report enhanced with attack strategies and recon data."""
    original: ParsedReport
    strategies: list[AttackStrategy] = field(default_factory=list)
    preflight: Optional[PreflightResult] = None
    enriched_prompt: str = ""           # The final prompt to give the agent
    payload_variants: list[str] = field(default_factory=list)
    inferred_endpoints: list[str] = field(default_factory=list)
    attempt_number: int = 1             # Incremented on retries
    previous_failures: list[str] = field(default_factory=list)


# ── Enrichment Prompt ────────────────────────────────────────────────

ENRICH_PROMPT = """You are a senior penetration tester preparing an attack plan.

## Original Vulnerability Report
- **Type:** {vuln_type}
- **Title:** {title}
- **Description:** {description}
- **Target:** {target_url}
- **Steps from report:**
{steps_text}

## Pre-flight Recon Results
{preflight_text}

## Your Task
Generate a battle-ready attack plan as JSON. Think like a real bug bounty hunter — what would YOU do to reproduce this?

Return JSON:
{{
    "strategies": [
        {{
            "name": "Strategy name",
            "description": "What this approach does",
            "priority": 1,
            "steps": [
                {{
                    "action": "make_request or browser_action",
                    "description": "What to do",
                    "url": "/api/endpoint",
                    "method": "POST",
                    "body": {{"key": "value"}},
                    "expected": "What a successful result looks like",
                    "on_failure": "What to try if this step fails"
                }}
            ],
            "fallback_note": "If this entire strategy fails, try..."
        }}
    ],
    "payload_variants": [
        "Primary payload",
        "Bypass variant 1 (URL encoded)",
        "Bypass variant 2 (case variation)",
        "Bypass variant 3 (alternative technique)"
    ],
    "inferred_endpoints": [
        "/api/likely-endpoint",
        "/another/possible-path"
    ],
    "key_observations": "Any insights about the target or vuln that would help the agent"
}}

## Rules
- Generate 2-3 strategies ordered by likelihood of success
- Strategy 1 should follow the report closely (if steps exist)
- Strategy 2 should be an alternative approach (different payload, different endpoint)
- Strategy 3 should be a blind/exploratory approach
- For EACH strategy, include concrete steps with exact URLs, methods, and payloads
- Generate 3-5 payload variants (original + bypasses like encoding, case changes, alternative tags)
- Infer likely API endpoints even if not in the report (e.g. /api/Users, /rest/user/login)
- Be specific — no vague instructions like "test the endpoint". Give exact requests.
- Return ONLY valid JSON
"""

REFINE_PROMPT = """You are a senior penetration tester reviewing a FAILED attack attempt.

## Original Report
- **Type:** {vuln_type}
- **Title:** {title}
- **Target:** {target_url}

## What Was Tried (Attempt #{attempt_number})
{previous_strategy}

## What Went Wrong
{failure_log}

## Your Task
Analyze the failure and generate a REVISED attack plan. Think about:
- Did the agent use the wrong password when logging in?
- Did the agent miss an endpoint or use the wrong URL?
- Was the payload filtered/blocked? What bypass would work?
- Did the agent waste steps on non-essential actions?
- Is there a completely different approach that might work?

Return JSON (same format as before):
{{
    "strategies": [...],
    "payload_variants": [...],
    "inferred_endpoints": [...],
    "key_observations": "What went wrong and how to fix it",
    "lessons_learned": "Specific mistakes to avoid in this retry"
}}

Return ONLY valid JSON.
"""


# ── Main Enricher Class ─────────────────────────────────────────────

class ReportEnricher:
    """
    Enriches parsed vulnerability reports with LLM-generated attack plans,
    pre-flight recon, and post-failure refinement.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "llama-4-scout-17b-16e-instruct",
        provider: str = "groq",
        verbose: bool = False,
    ):
        self.client = LLMClient(
            api_key=api_key,
            model=model,
            provider=provider,
            temperature=0.3,
            max_tokens=4096,
            verbose=verbose,
        )
        self.verbose = verbose

    # ── Pre-flight Recon ─────────────────────────────────────────────

    def preflight(self, report: ParsedReport, target_url: str) -> PreflightResult:
        """
        Quick HTTP checks before browser launch.
        - Is the target alive?
        - Does the vulnerable endpoint exist?
        - Auth required?
        """
        result = PreflightResult()

        # Check target is alive
        try:
            with httpx.Client(timeout=10, verify=False) as client:
                resp = client.get(target_url, headers={"User-Agent": "Resurface/2.0"})
                result.target_alive = True
                result.status_code = resp.status_code
                result.notes = f"Target alive ({resp.status_code})"
                logger.info(f"  ✈️  Preflight: target alive ({resp.status_code})")
        except httpx.HTTPStatusError as e:
            result.target_alive = True  # Server responded, just with error
            result.status_code = e.response.status_code
            if e.response.status_code in (401, 403):
                result.auth_required = True
                result.notes = f"Target responds with {e.response.status_code} (auth required)"
            else:
                result.notes = f"Target responds with {e.response.status_code}"
            logger.info(f"  ✈️  Preflight: target responded {e.response.status_code}")
        except Exception as e:
            result.notes = f"Target unreachable: {e}"
            logger.warning(f"  ✈️  Preflight: target unreachable — {e}")
            return result

        # Check specific vulnerable endpoint if we have one
        vuln_url = None
        for step in report.steps:
            if step.url:
                vuln_url = step.url
                break

        if vuln_url:
            # Resolve relative URL
            if vuln_url.startswith("/"):
                vuln_url = target_url.rstrip("/") + vuln_url

            try:
                with httpx.Client(timeout=10, verify=False) as client:
                    resp = client.get(vuln_url, headers={"User-Agent": "Resurface/2.0"})
                    result.endpoint_exists = True
                    result.endpoint_status = resp.status_code
                    logger.info(f"  ✈️  Preflight: endpoint exists ({resp.status_code})")
            except httpx.HTTPStatusError as e:
                result.endpoint_status = e.response.status_code
                if e.response.status_code == 404:
                    result.endpoint_exists = False
                    result.notes += f" | Endpoint {vuln_url} → 404 (may be removed)"
                    logger.info(f"  ✈️  Preflight: endpoint 404")
                elif e.response.status_code in (401, 403):
                    result.endpoint_exists = True
                    result.auth_required = True
                    result.notes += f" | Endpoint needs auth ({e.response.status_code})"
                    logger.info(f"  ✈️  Preflight: endpoint needs auth ({e.response.status_code})")
                elif e.response.status_code == 405:
                    result.endpoint_exists = True  # Exists but wrong method
                    result.notes += f" | Endpoint exists (405 — try POST)"
                    logger.info(f"  ✈️  Preflight: endpoint exists (405)")
                else:
                    result.endpoint_exists = True
                    result.notes += f" | Endpoint → {e.response.status_code}"
            except Exception as e:
                result.notes += f" | Endpoint check failed: {e}"

        return result

    # ── Enrichment ───────────────────────────────────────────────────

    def enrich(
        self,
        report: ParsedReport,
        target_url: str,
        preflight_result: Optional[PreflightResult] = None,
    ) -> EnrichedReport:
        """
        Enrich a parsed report with LLM-generated attack strategies.
        Returns an EnrichedReport with multiple strategies and payload variants.
        """
        logger.info(f"  🧪 Enriching report #{report.report_id}...")

        # Run preflight if not provided
        if preflight_result is None:
            preflight_result = self.preflight(report, target_url)

        # Build steps text for the prompt
        steps_text = ""
        if report.steps:
            for s in report.steps:
                steps_text += f"  {s.order}. {s.description}\n"
                if s.url:     steps_text += f"     URL: {s.url}\n"
                if s.method:  steps_text += f"     Method: {s.method}\n"
                if s.payload: steps_text += f"     Payload: {s.payload}\n"
                if s.body:    steps_text += f"     Body: {s.body}\n"
                if s.expected_behavior: steps_text += f"     Expected: {s.expected_behavior}\n"
        else:
            steps_text = "  (No specific steps in report — blind mode)"

        # Build preflight text
        pf = preflight_result
        preflight_text = (
            f"- Target alive: {'YES' if pf.target_alive else 'NO'} (HTTP {pf.status_code})\n"
            f"- Auth required: {'YES' if pf.auth_required else 'NO'}\n"
            f"- Vulnerable endpoint exists: {'YES' if pf.endpoint_exists else 'UNKNOWN'}"
            f" (HTTP {pf.endpoint_status})\n" if pf.endpoint_status else "\n"
        )
        if pf.notes:
            preflight_text += f"- Notes: {pf.notes}\n"

        # Call LLM via unified client
        prompt = ENRICH_PROMPT.format(
            vuln_type=report.vuln_type.value,
            title=report.title,
            description=report.description,
            target_url=target_url,
            steps_text=steps_text,
            preflight_text=preflight_text,
        )

        data = self.client.call_json(prompt, label="Enricher")

        # Parse LLM response
        enriched = EnrichedReport(original=report, preflight=preflight_result)

        if data:
            # Parse strategies
            for s in data.get("strategies", []):
                enriched.strategies.append(AttackStrategy(
                    name=s.get("name", "Unknown"),
                    description=s.get("description", ""),
                    steps=s.get("steps", []),
                    payloads=s.get("payloads", []),
                    fallback_note=s.get("fallback_note", ""),
                    priority=s.get("priority", 1),
                ))

            enriched.payload_variants = data.get("payload_variants", [])
            enriched.inferred_endpoints = data.get("inferred_endpoints", [])

            # Build the enriched prompt for the agent
            enriched.enriched_prompt = self._build_enriched_prompt(
                report, enriched, target_url, preflight_result
            )

            logger.info(
                f"  🧪 Enriched: {len(enriched.strategies)} strategies, "
                f"{len(enriched.payload_variants)} payloads, "
                f"{len(enriched.inferred_endpoints)} endpoints"
            )
        else:
            logger.warning("  🧪 Enrichment LLM call failed — using original prompt")

        return enriched

    # ── Post-Failure Refinement ──────────────────────────────────────

    def refine(
        self,
        enriched: EnrichedReport,
        failure_log: str,
        target_url: str,
    ) -> EnrichedReport:
        """
        After a failed replay attempt, analyze what went wrong and generate
        a revised attack plan.
        """
        enriched.attempt_number += 1
        enriched.previous_failures.append(failure_log[:2000])

        logger.info(f"  🔄 Refining after attempt #{enriched.attempt_number - 1}...")

        # Summarize previous strategy
        prev_strategy = ""
        if enriched.strategies:
            s = enriched.strategies[0]
            prev_strategy = f"Strategy: {s.name}\n"
            for step in s.steps:
                prev_strategy += f"  - {step.get('description', '?')}\n"

        prompt = REFINE_PROMPT.format(
            vuln_type=enriched.original.vuln_type.value,
            title=enriched.original.title,
            target_url=target_url,
            attempt_number=enriched.attempt_number - 1,
            previous_strategy=prev_strategy or "(No structured strategy — used default prompt)",
            failure_log=failure_log[:3000],
        )

        data = self.client.call_json(prompt, label="Enricher Refine")

        if data:
            # Replace strategies with refined ones
            enriched.strategies = []
            for s in data.get("strategies", []):
                enriched.strategies.append(AttackStrategy(
                    name=s.get("name", "Unknown"),
                    description=s.get("description", ""),
                    steps=s.get("steps", []),
                    payloads=s.get("payloads", []),
                    fallback_note=s.get("fallback_note", ""),
                    priority=s.get("priority", 1),
                ))

            # Merge new payloads (keep old ones too)
            new_payloads = data.get("payload_variants", [])
            enriched.payload_variants = list(set(enriched.payload_variants + new_payloads))

            new_endpoints = data.get("inferred_endpoints", [])
            enriched.inferred_endpoints = list(set(enriched.inferred_endpoints + new_endpoints))

            # Rebuild prompt with lessons learned
            lessons = data.get("lessons_learned", "")
            observations = data.get("key_observations", "")

            enriched.enriched_prompt = self._build_enriched_prompt(
                enriched.original, enriched, target_url, enriched.preflight,
                extra_context=(
                    f"\n## LESSONS FROM PREVIOUS FAILURE (Attempt #{enriched.attempt_number - 1})\n"
                    f"{lessons}\n{observations}\n"
                    f"DO NOT repeat these mistakes. Try a different approach.\n"
                ),
            )

            logger.info(
                f"  🔄 Refined: {len(enriched.strategies)} new strategies, "
                f"attempt #{enriched.attempt_number}"
            )
        else:
            logger.warning("  🔄 Refinement LLM call failed")

        return enriched

    # ── Prompt Builder ───────────────────────────────────────────────

    def _build_enriched_prompt(
        self,
        report: ParsedReport,
        enriched: EnrichedReport,
        target_url: str,
        preflight: Optional[PreflightResult],
        extra_context: str = "",
    ) -> str:
        """Build the final enriched prompt for the browser agent."""

        # Strategies section
        strategies_text = ""
        for i, s in enumerate(enriched.strategies, 1):
            strategies_text += f"\n### Strategy {i}: {s.name} (Priority: {s.priority})\n"
            strategies_text += f"{s.description}\n"
            for j, step in enumerate(s.steps, 1):
                strategies_text += f"  {j}. {step.get('description', '?')}\n"
                if step.get('url'):
                    strategies_text += f"     URL: {step['url']}\n"
                if step.get('method'):
                    strategies_text += f"     Method: {step['method']}\n"
                if step.get('body'):
                    strategies_text += f"     Body: {json.dumps(step['body']) if isinstance(step['body'], dict) else step['body']}\n"
                if step.get('expected'):
                    strategies_text += f"     ✅ Success: {step['expected']}\n"
                if step.get('on_failure'):
                    strategies_text += f"     ❌ If fails: {step['on_failure']}\n"
            if s.fallback_note:
                strategies_text += f"  ⚠️ Fallback: {s.fallback_note}\n"

        # Payload variants section
        payloads_text = ""
        if enriched.payload_variants:
            payloads_text = "\n## Payload Variants (try in order)\n"
            for i, p in enumerate(enriched.payload_variants, 1):
                payloads_text += f"  {i}. {p}\n"

        # Inferred endpoints section
        endpoints_text = ""
        if enriched.inferred_endpoints:
            endpoints_text = "\n## Known/Inferred Endpoints\n"
            for ep in enriched.inferred_endpoints:
                endpoints_text += f"  - {ep}\n"

        # Preflight section
        preflight_text = ""
        if preflight:
            preflight_text = "\n## Pre-flight Recon\n"
            preflight_text += f"  - Target: {'ALIVE' if preflight.target_alive else 'DOWN'}\n"
            if preflight.auth_required:
                preflight_text += f"  - ⚠️ Auth required (got {preflight.endpoint_status})\n"
            if preflight.endpoint_exists is False:
                preflight_text += f"  - ⚠️ Original endpoint returned 404 — may need different path\n"
            if preflight.notes:
                preflight_text += f"  - Notes: {preflight.notes}\n"

        prompt = (
            f"You are a security tester. Your mission: reproduce a known vulnerability.\n\n"
            f"## Target: {target_url}\n"
            f"## Vulnerability: {report.vuln_type.value} — {report.title}\n"
            f"## Description: {report.description}\n"
            f"{preflight_text}"
            f"\n## ATTACK PLAN\n"
            f"Follow the strategies below in order. If Strategy 1 fails, try Strategy 2, etc.\n"
            f"{strategies_text}"
            f"{payloads_text}"
            f"{endpoints_text}"
            f"{extra_context}"
            f"\n## CRITICAL RULES\n"
            "1. CREDENTIAL TRACKING: When you create an account or get credentials, "
            "use save_note to store them. When logging in, use get_note to recall the EXACT password. "
            "NEVER guess a password — always use what you saved.\n"
            "2. EARLY REPORTING: If an API response already confirms the vuln (e.g. 'role:admin' in response), "
            "call report_vulnerability IMMEDIATELY. You don't need to complete ALL steps.\n"
            "3. FAILURE RECOVERY: If an action fails, READ the error. If login says 'Invalid password', "
            "use get_note to check the correct password. Do NOT create a new account unless necessary.\n"
            "4. EFFICIENCY: Don't waste steps. Skip cookie/welcome banners quickly. "
            "Prefer make_request for API calls over browser form filling.\n"
            "5. After typing in ANY input field, press Enter to submit.\n"
            "6. If you see popups/banners/snackbars, dismiss them first.\n"
            "7. Do NOT retry the same failing action more than twice — switch strategy.\n"
            "8. Use make_request for ALL API calls — it's faster and more reliable than browser forms.\n"
        )

        return prompt
