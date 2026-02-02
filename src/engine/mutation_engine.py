"""
LLM-Powered Adaptive Payload Mutation Engine

When a replay attempt fails (payload blocked, filtered, WAF detected), this engine
feeds the failure response back to the LLM to generate targeted bypass variants.

Adaptive loop: attempt → fail → analyze → mutate → retry (configurable max attempts)
"""
import json
import time
import urllib.request
import urllib.error
from typing import Optional, Callable
from loguru import logger

from src.models import MutationAttempt, MutationResult


# ---------------------------------------------------------------------------
# Prompt: analyze a blocked response and generate bypass variants
# ---------------------------------------------------------------------------
MUTATION_ANALYSIS_PROMPT = """You are an expert penetration tester specializing in WAF/filter bypass techniques.

## Context
A security payload was sent to a web application and was **blocked or filtered**.
Your job: analyze the response to understand what was filtered and generate bypass variants.

## Vulnerability Type
{vuln_type}

## Original Payload
```
{original_payload}
```

## HTTP Request Summary
```
{request_summary}
```

## Server Response (status {status_code})
```
{response_snippet}
```

## Previous Attempts That Also Failed
{previous_attempts}

## Your Task
1. **Analyze** what specific part of the payload was filtered/blocked (tags? event handlers? keywords? encoding?)
2. **Generate** {num_variants} bypass variant payloads that attempt to evade the specific filter you identified

Think about these bypass strategies (but choose intelligently based on what was actually blocked):
- HTML encoding variants (hex, decimal, unicode, mixed encoding)
- Tag alternatives (use less common tags: <svg>, <img>, <details>, <math>, <marquee>)
- Event handler alternatives (onfocus, onmouseover, onerror, onload, onanimationend)
- Case manipulation and null bytes
- Attribute injection without closing tags
- JavaScript protocol tricks (javascript:, data:, vbscript:)
- Template literal injection and string construction
- Whitespace and comment insertion within keywords
- Double encoding, overlong UTF-8
- Polyglot payloads that work in multiple contexts

Respond with JSON:
{{
    "filter_analysis": "<what specific filtering/WAF rules you identified>",
    "blocked_elements": ["<list of specific tokens/patterns that were blocked>"],
    "variants": [
        {{
            "payload": "<the bypass payload>",
            "strategy": "<short name: encoding_bypass, tag_alternative, event_handler_swap, case_trick, protocol_trick, polyglot, etc>",
            "rationale": "<why this specific variant might bypass the detected filter>"
        }}
    ]
}}

Return ONLY valid JSON. Generate creative, targeted bypasses — not generic lists.
Each variant should specifically address the filter you identified.
"""

# ---------------------------------------------------------------------------
# Prompt: analyze whether a response indicates the payload was blocked
# ---------------------------------------------------------------------------
BLOCK_DETECTION_PROMPT = """You are a security analyst. Determine if this HTTP response indicates the payload was blocked/filtered.

## Original Payload
```
{payload}
```

## HTTP Response (status {status_code})
```
{response_snippet}
```

Respond with JSON:
{{
    "blocked": <true/false>,
    "reason": "<why you think it was blocked or not>",
    "filter_type": "<waf_block, payload_stripped, payload_escaped, error_page, none>",
    "payload_reflected": <true/false — is the payload present unmodified in the response?>,
    "payload_modified": "<if the payload appears modified/escaped, show how>"
}}

Return ONLY valid JSON.
"""


class MutationEngine:
    """
    LLM-powered adaptive payload mutation engine.

    Implements: attempt → detect block → analyze filter → generate bypass → retry
    """

    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.0-flash",
        provider: str = "gemini",
        max_mutation_attempts: int = 5,
        variants_per_round: int = 3,
        temperature: float = 0.4,
        verbose: bool = False,
    ):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.max_mutation_attempts = max_mutation_attempts
        self.variants_per_round = variants_per_round
        self.temperature = temperature
        self.verbose = verbose

    # ------------------------------------------------------------------
    # LLM communication (same pattern as rest of codebase)
    # ------------------------------------------------------------------
    def _call_llm(self, prompt: str, max_retries: int = 5,
                  label: str = "Mutation Engine") -> Optional[str]:
        """Call LLM API (Gemini or Groq) with retry + exponential backoff"""
        if self.verbose:
            from src.utils.verbose import print_llm_prompt
            print_llm_prompt(prompt, label=label)
        
        for attempt in range(max_retries):
            try:
                if self.provider == "groq":
                    result = self._call_groq(prompt)
                else:
                    result = self._call_gemini(prompt)
                
                if self.verbose and result:
                    from src.utils.verbose import print_llm_response
                    print_llm_response(result, label=label)
                
                return result
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    wait = (2 ** attempt) * 5
                    logger.warning(f"Rate limited (429). Retrying in {wait}s... (attempt {attempt+1}/{max_retries})")
                    time.sleep(wait)
                    continue
                logger.error(f"LLM call failed: HTTP {e.code}")
                return None
            except Exception as e:
                logger.error(f"LLM call failed: {e}")
                return None
        logger.error(f"LLM API: max retries ({max_retries}) exhausted")
        return None

    def _call_gemini(self, prompt: str) -> Optional[str]:
        url = self.GEMINI_URL.format(model=self.model) + f"?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": 4096,
                "responseMimeType": "application/json",
            },
        }
        req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
        req.data = json.dumps(payload).encode()
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read())
        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts:
                return parts[0].get("text", "")
        return None

    def _call_groq(self, prompt: str) -> Optional[str]:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
        }
        req = urllib.request.Request(
            self.GROQ_URL,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Resurface/1.0",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        req.data = json.dumps(payload).encode()
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read())
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return None

    # ------------------------------------------------------------------
    # Heuristic block detection (fast, no LLM call)
    # ------------------------------------------------------------------
    @staticmethod
    def heuristic_block_detected(
        payload: str,
        status_code: Optional[int],
        response_body: str,
        response_headers: str = "",
    ) -> bool:
        """
        Quick heuristic check whether a payload was blocked/filtered.
        Used before calling the (more expensive) LLM analysis.
        """
        if not response_body and not status_code:
            return False

        # WAF-style status codes
        if status_code in (403, 406, 429, 503):
            waf_indicators = [
                "blocked", "forbidden", "waf", "firewall",
                "access denied", "security", "cloudflare",
                "akamai", "incapsula", "sucuri", "modsecurity",
                "not acceptable", "request rejected",
            ]
            body_lower = response_body.lower()
            headers_lower = response_headers.lower()
            for indicator in waf_indicators:
                if indicator in body_lower or indicator in headers_lower:
                    return True

        # Payload stripped — the payload (or its core signature) is absent from a 200 response
        if status_code == 200 and payload:
            # Check if payload was stripped (for reflected XSS, etc.)
            # Only check the core dangerous part, not the whole thing
            dangerous_tokens = ["<script", "onerror=", "onload=", "javascript:", "alert(", "confirm(", "prompt("]
            payload_lower = payload.lower()
            body_lower = response_body.lower()
            for token in dangerous_tokens:
                if token in payload_lower and token not in body_lower:
                    return True
            # Check if payload was HTML-escaped
            if "<" in payload and "&lt;" in response_body and "<script" not in response_body.lower():
                return True

        # Error messages mentioning security
        security_errors = [
            "invalid input", "illegal character", "xss detected",
            "potential attack", "input validation", "suspicious request",
            "dangerous content",
        ]
        body_lower = response_body.lower()
        for err in security_errors:
            if err in body_lower:
                return True

        return False

    # ------------------------------------------------------------------
    # LLM-based block detection (more accurate, costs a call)
    # ------------------------------------------------------------------
    def llm_block_detected(
        self,
        payload: str,
        status_code: Optional[int],
        response_body: str,
    ) -> dict:
        """
        Ask the LLM whether the response indicates the payload was blocked.
        Returns the parsed analysis dict, or a default if LLM fails.
        """
        prompt = BLOCK_DETECTION_PROMPT.format(
            payload=payload[:1000],
            status_code=status_code or "unknown",
            response_snippet=response_body[:3000],
        )
        raw = self._call_llm(prompt, label="Block Detection")
        if not raw:
            return {"blocked": False, "reason": "LLM unavailable", "filter_type": "none"}
        try:
            text = raw.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]
            return json.loads(text)
        except json.JSONDecodeError:
            return {"blocked": False, "reason": "LLM returned invalid JSON", "filter_type": "none"}

    # ------------------------------------------------------------------
    # Core: generate bypass variants via LLM
    # ------------------------------------------------------------------
    def _generate_variants(
        self,
        original_payload: str,
        vuln_type: str,
        request_summary: str,
        status_code: Optional[int],
        response_snippet: str,
        previous_attempts: list[MutationAttempt],
    ) -> list[dict]:
        """
        Ask the LLM to analyze the filter and generate bypass variants.
        Returns a list of dicts with keys: payload, strategy, rationale.
        """
        prev_text = "None" if not previous_attempts else "\n".join(
            f"  {a.attempt_number}. [{a.strategy}] `{a.mutated_payload[:120]}` → "
            f"status={a.status_code}, blocked={a.blocked}"
            for a in previous_attempts
        )

        prompt = MUTATION_ANALYSIS_PROMPT.format(
            vuln_type=vuln_type,
            original_payload=original_payload[:1000],
            request_summary=request_summary[:2000],
            status_code=status_code or "unknown",
            response_snippet=response_snippet[:3000],
            previous_attempts=prev_text,
            num_variants=self.variants_per_round,
        )

        raw = self._call_llm(prompt, label="Mutation Variants")
        if not raw:
            logger.error("Mutation engine: LLM returned no response")
            return []

        try:
            text = raw.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.error(f"Mutation engine: invalid JSON from LLM: {raw[:300]}")
            return []

        variants = parsed.get("variants", [])
        filter_analysis = parsed.get("filter_analysis", "")
        if filter_analysis:
            logger.info(f"  🔍 Filter analysis: {filter_analysis[:120]}")

        return variants

    # ------------------------------------------------------------------
    # Adaptive mutation loop
    # ------------------------------------------------------------------
    def adaptive_mutate(
        self,
        original_payload: str,
        vuln_type: str,
        request_summary: str,
        initial_status_code: Optional[int],
        initial_response: str,
        replay_fn: Callable[[str], tuple[Optional[int], str]],
        max_attempts: Optional[int] = None,
    ) -> MutationResult:
        """
        Adaptive mutation loop: generates bypasses and tests them.

        Args:
            original_payload:     The payload that was blocked
            vuln_type:            Vulnerability type string (e.g. "xss_reflected")
            request_summary:      The original request for context
            initial_status_code:  Status code from the blocked attempt
            initial_response:     Response body from the blocked attempt
            replay_fn:            Callable(payload) -> (status_code, response_body)
                                  Used to test each mutated payload
            max_attempts:         Override default max mutation attempts

        Returns:
            MutationResult with all attempts and whether a bypass was found
        """
        max_attempts = max_attempts or self.max_mutation_attempts
        result = MutationResult(original_payload=original_payload)
        attempts: list[MutationAttempt] = []
        attempt_num = 0
        current_status = initial_status_code
        current_response = initial_response

        logger.info(
            f"🧬 Starting adaptive mutation for payload: {original_payload[:60]}... "
            f"(max {max_attempts} rounds, {self.variants_per_round} variants/round)"
        )

        while attempt_num < max_attempts:
            # Generate bypass variants
            variants = self._generate_variants(
                original_payload=original_payload,
                vuln_type=vuln_type,
                request_summary=request_summary,
                status_code=current_status,
                response_snippet=current_response,
                previous_attempts=attempts,
            )

            if not variants:
                logger.warning("  Mutation engine: LLM produced no variants, stopping")
                break

            # Test each variant
            found_bypass = False
            for variant in variants:
                attempt_num += 1
                if attempt_num > max_attempts:
                    break

                mutated_payload = variant.get("payload", "")
                strategy = variant.get("strategy", "unknown")
                rationale = variant.get("rationale", "")

                if not mutated_payload:
                    continue

                logger.info(
                    f"  🧪 Attempt {attempt_num}/{max_attempts}: "
                    f"[{strategy}] {mutated_payload[:80]}..."
                )

                # Test the mutated payload
                try:
                    test_status, test_response = replay_fn(mutated_payload)
                except Exception as e:
                    logger.warning(f"  Replay function error: {e}")
                    test_status, test_response = None, str(e)

                # Check if this variant was also blocked
                blocked = self.heuristic_block_detected(
                    mutated_payload, test_status, test_response
                )

                attempt = MutationAttempt(
                    attempt_number=attempt_num,
                    original_payload=original_payload,
                    mutated_payload=mutated_payload,
                    strategy=strategy,
                    rationale=rationale,
                    response_snippet=test_response[:2000] if test_response else "",
                    status_code=test_status,
                    success=not blocked,
                    blocked=blocked,
                )
                attempts.append(attempt)

                if not blocked:
                    logger.info(
                        f"  ✅ Potential bypass found! [{strategy}] "
                        f"status={test_status}"
                    )
                    result.final_payload = mutated_payload
                    result.bypassed = True
                    found_bypass = True
                    break
                else:
                    logger.info(f"  ❌ Still blocked (status={test_status})")
                    # Update context for next round
                    current_status = test_status
                    current_response = test_response or ""

                # Small delay between attempts
                time.sleep(0.5)

            if found_bypass or attempt_num >= max_attempts:
                break

        result.attempts = attempts
        result.total_attempts = len(attempts)
        result.analysis_summary = (
            f"Tested {len(attempts)} mutation(s). "
            f"{'Bypass found!' if result.bypassed else 'No bypass found.'}"
        )

        logger.info(
            f"🧬 Mutation complete: {len(attempts)} attempts, "
            f"bypass={'YES' if result.bypassed else 'NO'}"
        )

        return result

    # ------------------------------------------------------------------
    # Convenience: check + mutate in one call
    # ------------------------------------------------------------------
    def check_and_mutate(
        self,
        payload: str,
        vuln_type: str,
        request_summary: str,
        status_code: Optional[int],
        response_body: str,
        response_headers: str,
        replay_fn: Callable[[str], tuple[Optional[int], str]],
        max_attempts: Optional[int] = None,
    ) -> Optional[MutationResult]:
        """
        Convenience method: checks if payload was blocked, and if so,
        runs the adaptive mutation loop.

        Returns MutationResult if mutation was attempted, None if payload
        was not blocked (no mutation needed).
        """
        # Quick heuristic check first
        if not self.heuristic_block_detected(
            payload, status_code, response_body, response_headers
        ):
            return None

        logger.info(f"🛡️ Payload appears blocked (status={status_code}), starting mutation engine")

        return self.adaptive_mutate(
            original_payload=payload,
            vuln_type=vuln_type,
            request_summary=request_summary,
            initial_status_code=status_code,
            initial_response=response_body,
            replay_fn=replay_fn,
            max_attempts=max_attempts,
        )
