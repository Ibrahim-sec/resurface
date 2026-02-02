"""
Regex/heuristic-based replay result validator — dumb baseline for comparison.

Uses simple string matching and status code checks instead of LLM analysis.
This WILL have high false positives and miss subtle vulnerabilities — that's the point.
Used with --no-llm to prove the LLM validator adds real value.
"""
import re
from loguru import logger

from src.models import ReplayReport, ReplayResult


# Common XSS indicators in response
XSS_INDICATORS = [
    '<script', 'alert(', 'confirm(', 'prompt(', 'onerror=', 'onload=',
    'onfocus=', 'onmouseover=', 'javascript:', '<svg', '<img',
    'document.cookie', 'document.location',
]

# Open redirect indicators
REDIRECT_INDICATORS = [
    'location:', 'redirect', 'window.location', 'meta http-equiv="refresh"',
]

# SSRF indicators
SSRF_INDICATORS = [
    'root:x:', '/etc/passwd', 'internal server', '127.0.0.1',
    'localhost', '169.254.169.254', 'metadata',
]

# SQL injection indicators
SQLI_INDICATORS = [
    'sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle',
    'unclosed quotation', 'syntax error', 'database error',
    'you have an error in your sql',
]

# Path traversal indicators
PATH_TRAVERSAL_INDICATORS = [
    'root:x:', '/etc/passwd', '../', 'boot.ini', 'win.ini',
]


class RegexValidator:
    """
    Validates replay results using simple heuristic checks.
    No LLM involved — deliberately crude for baseline comparison.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _check_xss(self, evidence_text: str, payload: str) -> tuple[bool, str]:
        """Check for XSS indicators in response."""
        text_lower = evidence_text.lower()

        # Check if payload appears reflected in response
        if payload and payload.lower() in text_lower:
            return True, f"Payload '{payload[:50]}' found reflected in response"

        # Check for common XSS patterns
        for indicator in XSS_INDICATORS:
            if indicator.lower() in text_lower:
                return True, f"XSS indicator '{indicator}' found in response"

        return False, "No XSS indicators found"

    def _check_redirect(self, evidence_text: str, status_code: int) -> tuple[bool, str]:
        """Check for open redirect indicators."""
        text_lower = evidence_text.lower()

        if status_code in (301, 302, 303, 307, 308):
            # Check if redirect goes to external domain
            location_match = re.search(r'location:\s*(https?://[^\s]+)', text_lower)
            if location_match:
                return True, f"Redirect to: {location_match.group(1)}"

        for indicator in REDIRECT_INDICATORS:
            if indicator.lower() in text_lower:
                return True, f"Redirect indicator '{indicator}' found"

        return False, "No redirect indicators found"

    def _check_ssrf(self, evidence_text: str) -> tuple[bool, str]:
        """Check for SSRF indicators."""
        text_lower = evidence_text.lower()
        for indicator in SSRF_INDICATORS:
            if indicator.lower() in text_lower:
                return True, f"SSRF indicator '{indicator}' found in response"
        return False, "No SSRF indicators found"

    def _check_sqli(self, evidence_text: str) -> tuple[bool, str]:
        """Check for SQL injection indicators."""
        text_lower = evidence_text.lower()
        for indicator in SQLI_INDICATORS:
            if indicator.lower() in text_lower:
                return True, f"SQLi indicator '{indicator}' found in response"
        return False, "No SQLi indicators found"

    def _check_generic(self, evidence_text: str, status_code: int,
                       payload: str) -> tuple[bool, str]:
        """Generic check: payload reflection + status code heuristic."""
        # Payload reflected
        if payload and payload.lower() in evidence_text.lower():
            return True, f"Payload reflected in response (status {status_code})"

        # Status code heuristics
        if status_code == 403:
            return False, f"403 Forbidden — likely blocked/fixed"
        if status_code == 404:
            return False, f"404 Not Found — endpoint may be removed"
        if status_code and 200 <= status_code < 300:
            return True, f"200 OK — endpoint accessible (could be vulnerable)"

        return False, f"Inconclusive (status {status_code})"

    def validate(self, replay_report: ReplayReport) -> ReplayReport:
        """
        Validate a replay report using heuristic checks.
        Updates the replay_report in-place and returns it.
        """
        parsed = replay_report.parsed_report
        vuln_type = parsed.vuln_type.value

        if self.verbose:
            from src.utils.verbose import print_verbose_info
            print_verbose_info(
                f"Heuristic validation for report {parsed.report_id} "
                f"(type={vuln_type}, {len(replay_report.evidence)} evidence items)"
            )

        # Collect all evidence text and payloads
        all_text = ""
        all_payloads = set()
        status_codes = []

        for ev in replay_report.evidence:
            if ev.response_received:
                all_text += ev.response_received + "\n"
            if ev.status_code is not None:
                status_codes.append(ev.status_code)

        for step in parsed.steps:
            if step.payload:
                all_payloads.add(step.payload)

        # Pick primary payload
        primary_payload = list(all_payloads)[0] if all_payloads else ""
        primary_status = status_codes[0] if status_codes else 0

        # Run type-specific checks
        indicators = []
        vuln_detected = False
        reason = ""

        if 'xss' in vuln_type:
            vuln_detected, reason = self._check_xss(all_text, primary_payload)
            indicators.append(f"XSS check: {reason}")

        elif vuln_type == 'open_redirect':
            vuln_detected, reason = self._check_redirect(all_text, primary_status)
            indicators.append(f"Redirect check: {reason}")

        elif vuln_type == 'ssrf':
            vuln_detected, reason = self._check_ssrf(all_text)
            indicators.append(f"SSRF check: {reason}")

        elif vuln_type == 'sqli':
            vuln_detected, reason = self._check_sqli(all_text)
            indicators.append(f"SQLi check: {reason}")

        else:
            vuln_detected, reason = self._check_generic(
                all_text, primary_status, primary_payload
            )
            indicators.append(f"Generic check: {reason}")

        # Additional status code analysis
        if any(sc == 403 for sc in status_codes):
            indicators.append("403 responses detected — may be blocked")
        if any(sc == 404 for sc in status_codes):
            indicators.append("404 responses detected — endpoint may not exist")
        if any(200 <= sc < 300 for sc in status_codes):
            indicators.append("2xx responses — endpoint is accessible")

        # Determine result
        if not replay_report.evidence:
            replay_report.result = ReplayResult.INCONCLUSIVE
            replay_report.confidence = 0.1
            analysis = "No evidence collected — cannot determine vulnerability status."
        elif vuln_detected:
            replay_report.result = ReplayResult.VULNERABLE
            replay_report.confidence = 0.5  # Always medium — heuristics are unreliable
            analysis = f"HEURISTIC DETECTION: {reason}"
        elif any(sc == 403 for sc in status_codes):
            replay_report.result = ReplayResult.FIXED
            replay_report.confidence = 0.4
            analysis = "Endpoint returned 403 — appears to be blocked/fixed."
        elif any(sc == 404 for sc in status_codes):
            replay_report.result = ReplayResult.FIXED
            replay_report.confidence = 0.3
            analysis = "Endpoint returned 404 — appears to be removed."
        else:
            replay_report.result = ReplayResult.INCONCLUSIVE
            replay_report.confidence = 0.2
            analysis = "Heuristic checks inconclusive — no clear indicators found."

        analysis += "\n\nIndicators:\n" + "\n".join(f"  • {i}" for i in indicators)
        analysis += "\n\n⚠️ NOTE: This is regex/heuristic validation (--no-llm mode). Results are unreliable."
        replay_report.llm_analysis = analysis

        if self.verbose:
            from src.utils.verbose import print_verbose_info
            print_verbose_info(
                f"Heuristic result: {replay_report.result.value} "
                f"(confidence={replay_report.confidence:.0%})"
            )

        logger.info(
            f"[regex] Validation for {parsed.report_id}: "
            f"{replay_report.result.value} (confidence: {replay_report.confidence})"
        )

        return replay_report
