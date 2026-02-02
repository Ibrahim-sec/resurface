"""
Regex-based report parser — dumb baseline for comparison with LLM parser.

This parser uses simple regex/pattern matching instead of LLM intelligence.
It WILL be bad — that's the point. Used with --no-llm to prove LLM adds value.
"""
import re
from typing import Optional
from datetime import datetime
from loguru import logger

from src.models import (
    ParsedReport, PoC_Step, VulnType, ReplayMethod
)


# Common XSS payloads to look for
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'<img[^>]+onerror\s*=',
    r'<svg[^>]+onload\s*=',
    r'javascript:',
    r'alert\s*\(',
    r'confirm\s*\(',
    r'prompt\s*\(',
    r'on\w+\s*=\s*["\']',
    r'<iframe[^>]*>',
]

# URL pattern
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'`\)]+',
    re.IGNORECASE
)

# HTTP method patterns
METHOD_PATTERNS = {
    'GET': re.compile(r'\b(?:send\s+a\s+)?GET\s+(?:request|to)\b', re.IGNORECASE),
    'POST': re.compile(r'\b(?:send\s+a\s+)?POST\s+(?:request|to|data)\b', re.IGNORECASE),
    'PUT': re.compile(r'\b(?:send\s+a\s+)?PUT\s+(?:request|to)\b', re.IGNORECASE),
    'DELETE': re.compile(r'\b(?:send\s+a\s+)?DELETE\s+(?:request|to)\b', re.IGNORECASE),
    'PATCH': re.compile(r'\b(?:send\s+a\s+)?PATCH\s+(?:request|to)\b', re.IGNORECASE),
}

# Vuln type keyword mapping (very crude)
VULN_KEYWORDS = {
    VulnType.XSS_REFLECTED: ['reflected xss', 'xss', 'cross-site scripting', 'cross site scripting'],
    VulnType.XSS_STORED: ['stored xss', 'persistent xss'],
    VulnType.XSS_DOM: ['dom xss', 'dom-based', 'dom based'],
    VulnType.IDOR: ['idor', 'insecure direct object', 'direct object reference'],
    VulnType.SSRF: ['ssrf', 'server-side request forgery', 'server side request'],
    VulnType.OPEN_REDIRECT: ['open redirect', 'url redirect', 'redirect'],
    VulnType.CSRF: ['csrf', 'cross-site request forgery'],
    VulnType.SQLI: ['sql injection', 'sqli', "sql'"],
    VulnType.INFO_DISCLOSURE: ['information disclosure', 'info disclosure', 'data leak'],
    VulnType.PATH_TRAVERSAL: ['path traversal', 'directory traversal', '../'],
    VulnType.RCE: ['remote code execution', 'rce', 'command injection'],
    VulnType.AUTH_BYPASS: ['auth bypass', 'authentication bypass'],
    VulnType.PRIVILEGE_ESCALATION: ['privilege escalation', 'privesc'],
}


class RegexParser:
    """
    Parses bug bounty reports using only regex/pattern matching.
    No LLM involved — deliberately crude for baseline comparison.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _detect_vuln_type(self, text: str, weakness: str) -> VulnType:
        """Try to detect vulnerability type from text keywords."""
        combined = (text + " " + weakness).lower()

        # Check weakness field first (more reliable)
        for vtype, keywords in VULN_KEYWORDS.items():
            for kw in keywords:
                if kw in weakness.lower():
                    return vtype

        # Fallback to report text
        for vtype, keywords in VULN_KEYWORDS.items():
            for kw in keywords:
                if kw in combined:
                    return vtype

        return VulnType.UNKNOWN

    def _extract_urls(self, text: str) -> list[str]:
        """Extract URLs from text using regex."""
        urls = URL_PATTERN.findall(text)
        # Clean up trailing punctuation
        cleaned = []
        for url in urls:
            url = url.rstrip('.,;:!?)')
            if len(url) > 10:  # Skip very short "URLs"
                cleaned.append(url)
        return list(dict.fromkeys(cleaned))  # deduplicate preserving order

    def _extract_payloads(self, text: str) -> list[str]:
        """Extract potential exploit payloads from text using regex."""
        payloads = []
        for pattern in XSS_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            payloads.extend(matches)

        # Also look for code blocks that might contain payloads
        code_blocks = re.findall(r'```[^\n]*\n(.*?)```', text, re.DOTALL)
        for block in code_blocks:
            block = block.strip()
            if any(p in block.lower() for p in ['<script', 'alert(', 'onerror', 'curl ', 'fetch(']):
                payloads.append(block)

        # Look for inline code with payloads
        inline_code = re.findall(r'`([^`]+)`', text)
        for code in inline_code:
            if any(p in code.lower() for p in ['<script', 'alert(', '<img', '<svg', 'javascript:']):
                payloads.append(code)

        return list(dict.fromkeys(payloads))  # deduplicate

    def _detect_method(self, text: str) -> str:
        """Try to detect HTTP method from text."""
        for method, pattern in METHOD_PATTERNS.items():
            if pattern.search(text):
                return method
        # Default based on content
        if any(kw in text.lower() for kw in ['post', 'submit', 'form', 'body', 'data']):
            return 'POST'
        return 'GET'

    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        match = re.match(r'https?://([^/\s:]+)', url)
        if match:
            return match.group(1)
        return None

    def _needs_browser(self, text: str, vuln_type: VulnType) -> bool:
        """Heuristic: does this need a browser?"""
        browser_keywords = ['browser', 'click', 'visit', 'open the', 'navigate to',
                           'dom', 'javascript:', 'onclick', 'page load']
        if vuln_type in (VulnType.XSS_DOM, VulnType.CSRF):
            return True
        text_lower = text.lower()
        return any(kw in text_lower for kw in browser_keywords)

    def parse_report(self, report: dict) -> Optional[ParsedReport]:
        """
        Parse a raw HackerOne report using regex/pattern matching only.
        Deliberately crude — no LLM intelligence.
        """
        report_id = report.get('id', 0)
        title = report.get('title', 'Unknown')
        severity = report.get('severity_rating', 'none')
        weakness = report.get('weakness', {})
        weakness_name = (weakness.get('name', '') if weakness else '')
        vuln_info = report.get('vulnerability_information', '') or ''

        if not vuln_info or len(vuln_info) < 30:
            logger.warning(f"[regex] Report {report_id} has insufficient content")
            return None

        if self.verbose:
            from src.utils.verbose import print_verbose_info
            print_verbose_info(f"Regex parsing report {report_id}: {title[:50]}")

        # Detect vuln type
        vuln_type = self._detect_vuln_type(vuln_info + " " + title, weakness_name)

        # Extract URLs
        urls = self._extract_urls(vuln_info)
        target_url = urls[0] if urls else None
        target_domain = self._extract_domain(target_url) if target_url else None

        # Extract payloads
        payloads = self._extract_payloads(vuln_info)

        # Detect HTTP method
        method = self._detect_method(vuln_info)

        # Determine replay method
        needs_browser = self._needs_browser(vuln_info, vuln_type)
        replay_method = ReplayMethod.BROWSER if needs_browser else ReplayMethod.HTTP

        # Build crude steps
        steps = []
        step_num = 1

        # Step 1: Navigate/request the target URL
        if target_url:
            steps.append(PoC_Step(
                order=step_num,
                description=f"Send {method} request to target URL",
                method=method,
                url=target_url,
                payload=payloads[0] if payloads else None,
                expected_behavior="Check for vulnerability indicators",
            ))
            step_num += 1

        # Additional steps for extra URLs
        for url in urls[1:4]:  # Max 3 additional URLs
            steps.append(PoC_Step(
                order=step_num,
                description=f"Request additional URL found in report",
                method='GET',
                url=url,
                expected_behavior="Check response",
            ))
            step_num += 1

        # If no URLs found, create a generic step
        if not steps:
            steps.append(PoC_Step(
                order=1,
                description="Could not extract clear PoC steps from report",
                method='GET',
                payload=payloads[0] if payloads else None,
                expected_behavior="Unknown",
            ))

        # Crude auth detection
        requires_auth = any(kw in vuln_info.lower() for kw in
                          ['login', 'authenticated', 'session', 'cookie', 'token', 'auth'])

        # Extract a crude description (first sentence-ish)
        description = vuln_info[:200].split('\n')[0].strip()
        if len(description) < 20:
            description = title

        result = ParsedReport(
            report_id=report_id,
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            target_url=target_url,
            target_domain=target_domain,
            weakness=weakness_name,
            description=description,
            impact="Extracted via regex — impact unknown",
            steps=steps,
            replay_method=replay_method,
            requires_auth=requires_auth,
            auth_details=None,
            original_report_text=vuln_info,
            parsed_at=datetime.now(),
            confidence=0.3,  # Always low — regex parsing is unreliable
        )

        if self.verbose:
            from src.utils.verbose import print_verbose_info
            print_verbose_info(
                f"Regex result: type={vuln_type.value}, steps={len(steps)}, "
                f"urls={len(urls)}, payloads={len(payloads)}, confidence=0.3"
            )

        logger.info(
            f"[regex] Parsed report {report_id}: type={vuln_type.value}, "
            f"steps={len(steps)}, confidence=0.3"
        )

        return result

    def parse_batch(self, reports: list[dict], delay: float = 0.0) -> list[ParsedReport]:
        """Parse multiple reports with regex (no rate limiting needed)."""
        results = []
        for report in reports:
            parsed = self.parse_report(report)
            if parsed:
                results.append(parsed)
        logger.info(f"[regex] Batch complete: parsed {len(results)}/{len(reports)} reports")
        return results
