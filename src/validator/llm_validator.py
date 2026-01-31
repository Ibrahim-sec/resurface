"""
LLM-powered replay result validator — determines if a vulnerability still exists
"""
import json
import urllib.request
from typing import Optional
from loguru import logger

from src.models import ReplayReport, ReplayResult


VALIDATE_PROMPT = """You are a cybersecurity expert validating whether a vulnerability has been reproduced.

## Original Vulnerability
- **Title:** {title}
- **Type:** {vuln_type}
- **Description:** {description}
- **Expected behavior if vulnerable:** {expected_behavior}

## Replay Results
The following HTTP requests were sent and responses received during the replay attempt:

{evidence_text}

## Your Task
Analyze the replay evidence and determine if the vulnerability still exists.

Respond with JSON:
{{
    "result": "<one of: vulnerable, fixed, partial, inconclusive>",
    "confidence": <0.0 to 1.0>,
    "analysis": "<detailed explanation of your conclusion, referencing specific evidence>",
    "indicators": [
        "<list specific indicators that led to your conclusion>"
    ]
}}

## Guidelines
- **vulnerable**: The replay evidence clearly shows the vulnerability is present (e.g., XSS payload executed, IDOR returned unauthorized data, redirect to external domain occurred)
- **fixed**: The replay evidence shows the vulnerability has been patched (e.g., input is sanitized, access is properly denied, redirect is blocked)
- **partial**: The original vulnerability appears fixed but a bypass or variant might exist (e.g., some payloads blocked but not all, WAF detected but bypass possible)
- **inconclusive**: Cannot determine — maybe the endpoint changed, authentication failed, or the response is ambiguous

Return ONLY valid JSON.
"""


class LLMValidator:
    """Validates replay results using Gemini or Groq LLM"""
    
    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
    
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash",
                 confidence_threshold: float = 0.7, provider: str = "gemini"):
        self.api_key = api_key
        self.model = model
        self.confidence_threshold = confidence_threshold
        self.provider = provider
    
    def _call_llm(self, prompt: str, max_retries: int = 5) -> Optional[str]:
        """Call LLM API with retry + exponential backoff"""
        import time as _time
        
        for attempt in range(max_retries):
            try:
                if self.provider == "groq":
                    return self._call_groq(prompt)
                else:
                    return self._call_gemini(prompt)
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    wait = (2 ** attempt) * 5
                    logger.warning(f"Rate limited (429). Retrying in {wait}s... (attempt {attempt+1}/{max_retries})")
                    _time.sleep(wait)
                    continue
                else:
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
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 2048, "responseMimeType": "application/json"}
        }
        req = urllib.request.Request(url, headers={'Content-Type': 'application/json'})
        req.data = json.dumps(payload).encode()
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read())
        candidates = data.get('candidates', [])
        if candidates:
            parts = candidates[0].get('content', {}).get('parts', [])
            if parts:
                return parts[0].get('text', '')
        return None
    
    def _call_groq(self, prompt: str) -> Optional[str]:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 2048,
            "response_format": {"type": "json_object"}
        }
        req = urllib.request.Request(self.GROQ_URL, headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        })
        req.data = json.dumps(payload).encode()
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read())
        choices = data.get('choices', [])
        if choices:
            return choices[0].get('message', {}).get('content', '')
        return None
    
    def validate(self, replay_report: ReplayReport) -> ReplayReport:
        """
        Validate a replay report by analyzing the evidence with LLM.
        Updates the replay_report in-place and returns it.
        """
        parsed = replay_report.parsed_report
        
        # Build evidence text
        evidence_parts = []
        for ev in replay_report.evidence:
            part = f"### Step {ev.step_number}\n"
            if ev.request_sent:
                part += f"**Request:**\n```\n{ev.request_sent[:2000]}\n```\n"
            if ev.response_received:
                part += f"**Response (HTTP {ev.status_code}):**\n```\n{ev.response_received[:3000]}\n```\n"
            if ev.notes:
                part += f"**Notes:** {ev.notes}\n"
            evidence_parts.append(part)
        
        evidence_text = "\n".join(evidence_parts) if evidence_parts else "No evidence collected."
        
        # Get expected behavior from steps
        expected_behaviors = []
        for step in parsed.steps:
            if step.expected_behavior:
                expected_behaviors.append(f"Step {step.order}: {step.expected_behavior}")
        expected_behavior = "\n".join(expected_behaviors) if expected_behaviors else "Not specified"
        
        # Build prompt
        prompt = VALIDATE_PROMPT.format(
            title=parsed.title,
            vuln_type=parsed.vuln_type.value,
            description=parsed.description,
            expected_behavior=expected_behavior,
            evidence_text=evidence_text[:8000]
        )
        
        logger.info(f"Validating replay for report {parsed.report_id}...")
        
        # Call LLM
        response_text = self._call_llm(prompt)
        if not response_text:
            replay_report.result = ReplayResult.INCONCLUSIVE
            replay_report.llm_analysis = "Validation failed: no LLM response"
            return replay_report
        
        # Parse response
        try:
            text = response_text.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1]
                text = text.rsplit('```', 1)[0]
            
            result = json.loads(text)
        except json.JSONDecodeError:
            replay_report.result = ReplayResult.INCONCLUSIVE
            replay_report.llm_analysis = f"Validation failed: invalid JSON response"
            return replay_report
        
        # Update replay report
        try:
            replay_report.result = ReplayResult(result.get('result', 'inconclusive'))
        except ValueError:
            replay_report.result = ReplayResult.INCONCLUSIVE
        
        replay_report.confidence = result.get('confidence', 0.0)
        
        analysis = result.get('analysis', '')
        indicators = result.get('indicators', [])
        if indicators:
            analysis += "\n\nKey Indicators:\n" + "\n".join(f"  • {i}" for i in indicators)
        replay_report.llm_analysis = analysis
        
        logger.info(
            f"Validation result for {parsed.report_id}: "
            f"{replay_report.result.value} (confidence: {replay_report.confidence})"
        )
        
        return replay_report
