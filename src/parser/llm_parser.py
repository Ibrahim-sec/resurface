"""
LLM-powered report parser — extracts structured PoC steps from raw reports
"""
import json
import urllib.request
from typing import Optional
from datetime import datetime
from loguru import logger

from src.models import (
    ParsedReport, PoC_Step, VulnType, ReplayMethod
)


PARSE_PROMPT = """You are a cybersecurity expert analyzing a disclosed bug bounty report. Your job is to extract structured, reproducible information from the report.

## Report Details
- **Title:** {title}
- **Platform:** HackerOne
- **Program:** {team}
- **Severity:** {severity}
- **Weakness Category:** {weakness}

## Report Content
{vulnerability_information}

---

## Your Task
Analyze this report and extract the following as JSON:

{{
    "vuln_type": "<one of: xss_reflected, xss_stored, xss_dom, idor, ssrf, open_redirect, csrf, sqli, info_disclosure, path_traversal, rce, auth_bypass, privilege_escalation, unknown>",
    "target_url": "<the main URL/endpoint being targeted, or null>",
    "target_domain": "<the target domain, or null>",
    "description": "<brief description of the vulnerability in 1-2 sentences>",
    "impact": "<what an attacker could achieve>",
    "requires_auth": <true/false - does the PoC need authentication?>,
    "auth_details": "<what kind of auth is needed, or null>",
    "replay_method": "<http or browser - does this need a real browser or just HTTP requests?>",
    "confidence": <0.0 to 1.0 - how confident are you that the PoC steps are complete and reproducible?>,
    "steps": [
        {{
            "order": 1,
            "description": "<what to do in this step>",
            "method": "<HTTP method: GET/POST/PUT/DELETE or null for browser actions>",
            "url": "<full URL for this step, or null>",
            "headers": {{}},
            "params": {{}},
            "body": "<request body if POST, or null>",
            "payload": "<the actual exploit payload if any, or null>",
            "expected_behavior": "<what should happen if the vulnerability exists>",
            "browser_action": "<for browser-based: describe the browser action, or null>"
        }}
    ]
}}

## Rules
- Extract EXACT URLs, payloads, and parameters from the report
- If the report mentions specific endpoints, include them verbatim
- If steps are unclear or missing, set confidence lower
- For XSS: always include the exact payload
- For IDOR: include the parameter that needs to be changed and what values to use
- For SSRF: include the callback/target URL pattern
- If the report has multiple PoCs, use the most impactful one
- Return ONLY valid JSON, no markdown or explanation
"""


class LLMParser:
    """Parses bug bounty reports using Gemini LLM"""
    
    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash",
                 temperature: float = 0.1):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
    
    def _call_gemini(self, prompt: str) -> Optional[str]:
        """Call Gemini API and return the text response"""
        url = self.GEMINI_URL.format(model=self.model) + f"?key={self.api_key}"
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": 4096,
                "responseMimeType": "application/json"
            }
        }
        
        try:
            req = urllib.request.Request(url, headers={
                'Content-Type': 'application/json'
            })
            req.data = json.dumps(payload).encode()
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read())
            
            # Extract text from Gemini response
            candidates = data.get('candidates', [])
            if candidates:
                parts = candidates[0].get('content', {}).get('parts', [])
                if parts:
                    return parts[0].get('text', '')
            
            logger.error(f"Unexpected Gemini response structure: {data}")
            return None
            
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            return None
    
    def parse_report(self, report: dict) -> Optional[ParsedReport]:
        """
        Parse a raw HackerOne report into structured PoC steps.
        
        Args:
            report: Raw HackerOne report dict (from .json endpoint)
        
        Returns:
            ParsedReport with extracted PoC steps, or None on failure
        """
        report_id = report.get('id', 0)
        title = report.get('title', 'Unknown')
        severity = report.get('severity_rating', 'none')
        team = report.get('team', {}).get('handle', 'Unknown')
        weakness = report.get('weakness', {})
        weakness_name = weakness.get('name', 'Unknown') if weakness else 'Unknown'
        vuln_info = report.get('vulnerability_information', '') or ''
        
        if not vuln_info or len(vuln_info) < 50:
            logger.warning(f"Report {report_id} has insufficient content ({len(vuln_info)} chars)")
            return None
        
        # Build prompt
        prompt = PARSE_PROMPT.format(
            title=title,
            team=team,
            severity=severity,
            weakness=weakness_name,
            vulnerability_information=vuln_info[:8000]  # Limit to avoid token overflow
        )
        
        logger.info(f"Parsing report {report_id}: {title[:50]}...")
        
        # Call LLM
        response_text = self._call_gemini(prompt)
        if not response_text:
            logger.error(f"No response from LLM for report {report_id}")
            return None
        
        # Parse JSON response
        try:
            # Clean response — sometimes LLM wraps in markdown code blocks
            text = response_text.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1]  # Remove first line
                text = text.rsplit('```', 1)[0]  # Remove last ```
            
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON for report {report_id}: {e}")
            logger.debug(f"Raw LLM response: {response_text[:500]}")
            return None
        
        # Convert to ParsedReport
        try:
            vuln_type = VulnType(parsed.get('vuln_type', 'unknown'))
        except ValueError:
            vuln_type = VulnType.UNKNOWN
        
        try:
            replay_method = ReplayMethod(parsed.get('replay_method', 'http'))
        except ValueError:
            replay_method = ReplayMethod.HTTP
        
        steps = []
        for s in parsed.get('steps', []):
            steps.append(PoC_Step(
                order=s.get('order', 0),
                description=s.get('description', ''),
                method=s.get('method'),
                url=s.get('url'),
                headers=s.get('headers', {}),
                params=s.get('params', {}),
                body=s.get('body'),
                payload=s.get('payload'),
                expected_behavior=s.get('expected_behavior'),
                browser_action=s.get('browser_action')
            ))
        
        result = ParsedReport(
            report_id=report_id,
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            target_url=parsed.get('target_url'),
            target_domain=parsed.get('target_domain'),
            weakness=weakness_name,
            description=parsed.get('description', ''),
            impact=parsed.get('impact', ''),
            steps=steps,
            replay_method=replay_method,
            requires_auth=parsed.get('requires_auth', False),
            auth_details=parsed.get('auth_details'),
            original_report_text=vuln_info,
            parsed_at=datetime.now(),
            confidence=parsed.get('confidence', 0.0)
        )
        
        logger.info(
            f"Parsed report {report_id}: type={vuln_type.value}, "
            f"steps={len(steps)}, method={replay_method.value}, "
            f"confidence={result.confidence}"
        )
        
        return result
    
    def parse_batch(self, reports: list[dict], delay: float = 1.0) -> list[ParsedReport]:
        """Parse multiple reports with rate limiting"""
        import time
        
        results = []
        for i, report in enumerate(reports):
            parsed = self.parse_report(report)
            if parsed:
                results.append(parsed)
            
            if i < len(reports) - 1:
                time.sleep(delay)
            
            if (i + 1) % 10 == 0:
                logger.info(f"Batch progress: {i + 1}/{len(reports)}, parsed: {len(results)}")
        
        logger.info(f"Batch complete: parsed {len(results)}/{len(reports)} reports")
        return results
