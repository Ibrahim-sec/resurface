"""
LLM-Powered Adaptive Payload Mutation Engine

When a replay attempt fails (payload blocked, filtered, WAF detected), this engine
feeds the failure response back to the LLM to generate targeted bypass variants.

Uses instructor for guaranteed Pydantic structured output.
"""
import time
from typing import Optional, Callable
from loguru import logger

from src.models import (
    MutationAttempt, MutationResult,
    LLMBlockDetection, LLMMutationAnalysis
)
from src.llm import LLMClient
from src.prompts import format_prompt


class MutationEngine:
    """
    LLM-powered adaptive payload mutation engine with structured output.
    
    Implements: attempt → detect block → analyze filter → generate bypass → retry
    """

    def __init__(
        self,
        api_key: str,
        model: str = "llama-4-scout-17b-16e-instruct",
        provider: str = "groq",
        max_mutation_attempts: int = 5,
        variants_per_round: int = 3,
        temperature: float = 0.4,
        verbose: bool = False,
    ):
        self.client = LLMClient(
            api_key=api_key,
            model=model,
            provider=provider,
            temperature=temperature,
            max_tokens=4096,
            verbose=verbose,
        )
        self.max_mutation_attempts = max_mutation_attempts
        self.variants_per_round = variants_per_round
        self.verbose = verbose

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
        """Quick heuristic check whether a payload was blocked/filtered."""
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

        # Payload stripped
        if status_code == 200 and payload:
            dangerous_tokens = ["<script", "onerror=", "onload=", "javascript:", "alert(", "confirm(", "prompt("]
            payload_lower = payload.lower()
            body_lower = response_body.lower()
            for token in dangerous_tokens:
                if token in payload_lower and token not in body_lower:
                    return True
            if "<" in payload and "&lt;" in response_body and "<script" not in response_body.lower():
                return True

        # Security error messages
        security_errors = [
            "invalid input", "illegal character", "xss detected",
            "potential attack", "input validation", "suspicious request",
        ]
        body_lower = response_body.lower()
        for err in security_errors:
            if err in body_lower:
                return True

        return False

    # ------------------------------------------------------------------
    # LLM-based block detection with structured output
    # ------------------------------------------------------------------
    def llm_block_detected(
        self,
        payload: str,
        status_code: Optional[int],
        response_body: str,
    ) -> LLMBlockDetection:
        """Ask the LLM whether the response indicates blocking."""
        prompt = format_prompt(
            "block_detection",
            payload=payload[:1000],
            status_code=status_code or "unknown",
            response_snippet=response_body[:3000],
        )
        
        result = self.client.call_structured(
            prompt=prompt,
            response_model=LLMBlockDetection,
            label="Block Detection"
        )
        
        if not result:
            return LLMBlockDetection(
                blocked=False,
                reason="LLM unavailable",
                filter_type="none",
                payload_reflected=False
            )
        
        return result

    # ------------------------------------------------------------------
    # Generate bypass variants with structured output
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
        """Generate bypass variants using LLM with structured output."""
        prev_text = "None" if not previous_attempts else "\n".join(
            f"  {a.attempt_number}. [{a.strategy}] `{a.mutated_payload[:120]}` → "
            f"status={a.status_code}, blocked={a.blocked}"
            for a in previous_attempts
        )

        prompt = format_prompt(
            "mutation_analysis",
            vuln_type=vuln_type,
            original_payload=original_payload[:1000],
            request_summary=request_summary[:2000],
            status_code=status_code or "unknown",
            response_snippet=response_snippet[:3000],
            previous_attempts=prev_text,
        )
        
        # Add instruction for number of variants
        prompt += f"\n\nGenerate exactly {self.variants_per_round} bypass variants."

        result = self.client.call_structured(
            prompt=prompt,
            response_model=LLMMutationAnalysis,
            label="Mutation Variants"
        )
        
        if not result:
            logger.error("Mutation engine: LLM returned no response")
            return []

        if result.filter_analysis:
            logger.info(f"  🔍 Filter analysis: {result.filter_analysis[:120]}")

        return [
            {"payload": v.payload, "strategy": v.strategy, "rationale": v.rationale}
            for v in result.variants
        ]

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
        """Adaptive mutation loop: generates bypasses and tests them."""
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

                try:
                    test_status, test_response = replay_fn(mutated_payload)
                except Exception as e:
                    logger.warning(f"  Replay function error: {e}")
                    test_status, test_response = None, str(e)

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
                    logger.info(f"  ✅ Potential bypass found! [{strategy}] status={test_status}")
                    result.final_payload = mutated_payload
                    result.bypassed = True
                    found_bypass = True
                    break
                else:
                    logger.info(f"  ❌ Still blocked (status={test_status})")
                    current_status = test_status
                    current_response = test_response or ""

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
        """Convenience: checks if payload was blocked, runs mutation if so."""
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
