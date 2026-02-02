"""
Session Chaining Manager

Persists cookies and extracted values across replay steps.
Uses LLM to identify values to carry forward (CSRF tokens, session IDs, nonces).
Supports template substitution: steps can reference {{csrf_token}}, {{session_id}}, etc.
"""
import json
import re
import time
import urllib.request
import urllib.error
from http.cookiejar import CookieJar, Cookie
from typing import Optional
from loguru import logger

from src.models import SessionState


# ---------------------------------------------------------------------------
# Prompt: extract session-relevant values from an HTTP response
# ---------------------------------------------------------------------------
VALUE_EXTRACTION_PROMPT = """You are a security testing assistant. After an HTTP request, you need to extract values from the response that may be needed by subsequent requests.

## HTTP Request
```
{request_summary}
```

## HTTP Response (status {status_code})
### Headers
```
{response_headers}
```

### Body (first 4000 chars)
```
{response_body}
```

## Previously Extracted Values
{existing_values}

## Your Task
Identify values in this response that subsequent requests might need. Look for:
- CSRF tokens (in forms, headers, meta tags, JSON)
- Session identifiers
- User IDs, account IDs
- Nonces, state parameters
- OAuth tokens, bearer tokens
- Any dynamic values that appear in hidden form fields or JSON responses
- Redirect URLs / next-step URLs
- API keys exposed in responses

Respond with JSON:
{{
    "extracted_values": {{
        "<descriptive_name>": {{
            "value": "<the actual value>",
            "source": "<where you found it: header, form_field, json_body, meta_tag, cookie, url_param>",
            "description": "<what this value is for>"
        }}
    }},
    "cookies_to_set": {{
        "<cookie_name>": "<cookie_value>"
    }},
    "notes": "<any observations about the session state>"
}}

Use clear, template-friendly names: csrf_token, session_id, user_id, nonce, bearer_token, etc.
If no values need extracting, return empty dicts.
Return ONLY valid JSON.
"""


class SessionManager:
    """
    Manages session state across multi-step replay chains.

    Features:
    - Cookie jar that persists across steps
    - LLM-driven value extraction from responses
    - Template substitution for payloads and request bodies
    - Manual value injection
    """

    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(
        self,
        api_key: str = "",
        model: str = "gemini-2.0-flash",
        provider: str = "gemini",
        auto_extract: bool = True,
    ):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.auto_extract = auto_extract
        self.state = SessionState()
        self._cookie_jar = CookieJar()

    # ------------------------------------------------------------------
    # LLM communication
    # ------------------------------------------------------------------
    def _call_llm(self, prompt: str, max_retries: int = 5) -> Optional[str]:
        if not self.api_key:
            return None
        for attempt in range(max_retries):
            try:
                if self.provider == "groq":
                    return self._call_groq(prompt)
                else:
                    return self._call_gemini(prompt)
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    wait = (2 ** attempt) * 5
                    logger.warning(f"Rate limited (429). Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                logger.error(f"LLM call failed: HTTP {e.code}")
                return None
            except Exception as e:
                logger.error(f"LLM call failed: {e}")
                return None
        return None

    def _call_gemini(self, prompt: str) -> Optional[str]:
        url = self.GEMINI_URL.format(model=self.model) + f"?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 2048,
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
            "temperature": 0.1,
            "max_tokens": 2048,
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
    # Cookie management
    # ------------------------------------------------------------------
    def set_cookie(self, name: str, value: str, domain: str = "", path: str = "/"):
        """Manually set a cookie"""
        self.state.cookies[name] = value
        logger.debug(f"🍪 Cookie set: {name}={value[:30]}...")

    def get_cookies(self) -> dict:
        """Get all cookies as a dict"""
        return dict(self.state.cookies)

    def get_cookie_header(self) -> str:
        """Get cookies formatted as a Cookie header value"""
        if not self.state.cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in self.state.cookies.items())

    def update_cookies_from_headers(self, response_headers: str):
        """Parse Set-Cookie headers from a response and update the cookie jar"""
        for line in response_headers.split("\n"):
            line = line.strip()
            if line.lower().startswith("set-cookie:"):
                cookie_str = line.split(":", 1)[1].strip()
                # Parse the cookie name=value (ignore attributes like path, domain, etc.)
                cookie_part = cookie_str.split(";")[0].strip()
                if "=" in cookie_part:
                    name, value = cookie_part.split("=", 1)
                    self.state.cookies[name.strip()] = value.strip()
                    logger.debug(f"🍪 Cookie captured: {name.strip()}={value.strip()[:30]}...")

    # ------------------------------------------------------------------
    # Value extraction
    # ------------------------------------------------------------------
    def set_value(self, name: str, value: str):
        """Manually set an extracted value"""
        self.state.extracted_values[name] = value
        logger.debug(f"📌 Value set: {name}={value[:50]}...")

    def get_value(self, name: str) -> Optional[str]:
        """Get an extracted value by name"""
        return self.state.extracted_values.get(name)

    def get_all_values(self) -> dict:
        """Get all extracted values"""
        return dict(self.state.extracted_values)

    def extract_values_from_response(
        self,
        request_summary: str,
        status_code: Optional[int],
        response_headers: str,
        response_body: str,
    ):
        """
        Use LLM to extract session-relevant values from a response.
        Also parses Set-Cookie headers automatically.
        """
        # Always parse cookies from headers (no LLM needed)
        self.update_cookies_from_headers(response_headers)

        # Quick regex extraction for common patterns (no LLM needed)
        self._regex_extract(response_body)

        # LLM-based extraction for deeper analysis
        if not self.auto_extract or not self.api_key:
            return

        existing = (
            json.dumps(self.state.extracted_values, indent=2)
            if self.state.extracted_values
            else "None yet"
        )

        prompt = VALUE_EXTRACTION_PROMPT.format(
            request_summary=request_summary[:2000],
            status_code=status_code or "unknown",
            response_headers=response_headers[:2000],
            response_body=response_body[:4000],
            existing_values=existing,
        )

        raw = self._call_llm(prompt)
        if not raw:
            return

        try:
            text = raw.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Session manager: invalid JSON from LLM extraction")
            return

        # Process extracted values
        extracted = parsed.get("extracted_values", {})
        for name, info in extracted.items():
            if isinstance(info, dict):
                value = info.get("value", "")
            else:
                value = str(info)
            if value:
                self.state.extracted_values[name] = value
                logger.info(f"  📌 Extracted: {name} = {value[:50]}...")

        # Process cookies from LLM
        cookies = parsed.get("cookies_to_set", {})
        for name, value in cookies.items():
            if value:
                self.state.cookies[name] = value

        notes = parsed.get("notes", "")
        if notes:
            self.state.history.append(f"Extraction: {notes}")

    def _regex_extract(self, body: str):
        """Quick regex-based extraction for common tokens (no LLM cost)"""
        # CSRF tokens in hidden fields
        csrf_patterns = [
            r'name=["\']?csrf[_-]?token["\']?\s+value=["\']([^"\']+)["\']',
            r'name=["\']?_token["\']?\s+value=["\']([^"\']+)["\']',
            r'name=["\']?authenticity_token["\']?\s+value=["\']([^"\']+)["\']',
            r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']([^"\']+)["\']',
            # Also match value before name
            r'value=["\']([^"\']+)["\'].*?name=["\']?csrf[_-]?token["\']?',
            r'value=["\']([^"\']+)["\'].*?name=["\']?_token["\']?',
        ]
        for pattern in csrf_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                self.state.extracted_values["csrf_token"] = match.group(1)
                logger.debug(f"  📌 Regex extracted csrf_token: {match.group(1)[:30]}...")
                break

        # Meta CSRF tags
        meta_csrf = re.search(
            r'<meta\s+name=["\']csrf-token["\'].*?content=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE,
        )
        if meta_csrf:
            self.state.extracted_values["csrf_token"] = meta_csrf.group(1)

        # Nonce patterns
        nonce_match = re.search(
            r'name=["\']?nonce["\']?\s+value=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE,
        )
        if nonce_match:
            self.state.extracted_values["nonce"] = nonce_match.group(1)

    # ------------------------------------------------------------------
    # Template substitution
    # ------------------------------------------------------------------
    def substitute(self, text: str) -> str:
        """
        Replace {{variable_name}} placeholders with extracted values.
        Also replaces {{cookie:name}} with cookie values.
        """
        if not text or "{{" not in text:
            return text

        def replacer(match):
            key = match.group(1).strip()
            # Cookie reference: {{cookie:session_id}}
            if key.startswith("cookie:"):
                cookie_name = key[7:]
                return self.state.cookies.get(cookie_name, match.group(0))
            # Header reference: {{header:Authorization}}
            if key.startswith("header:"):
                header_name = key[7:]
                return self.state.headers.get(header_name, match.group(0))
            # Regular value
            return self.state.extracted_values.get(key, match.group(0))

        return re.sub(r"\{\{([^}]+)\}\}", replacer, text)

    def apply_to_step(self, step) -> None:
        """
        Apply template substitution to all string fields of a PoC_Step in-place.
        Also injects session cookies into headers.
        """
        if step.url:
            step.url = self.substitute(step.url)
        if step.body:
            step.body = self.substitute(step.body)
        if step.payload:
            step.payload = self.substitute(step.payload)
        if step.browser_action:
            step.browser_action = self.substitute(step.browser_action)

        # Substitute in params
        if step.params:
            step.params = {k: self.substitute(str(v)) for k, v in step.params.items()}

        # Substitute in headers
        if step.headers:
            step.headers = {k: self.substitute(str(v)) for k, v in step.headers.items()}

        # Inject session cookies
        cookie_header = self.get_cookie_header()
        if cookie_header:
            existing_cookies = step.headers.get("Cookie", "")
            if existing_cookies:
                step.headers["Cookie"] = f"{existing_cookies}; {cookie_header}"
            else:
                step.headers["Cookie"] = cookie_header

        # Inject persistent headers
        for k, v in self.state.headers.items():
            if k not in step.headers:
                step.headers[k] = v

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------
    def reset(self):
        """Reset all session state"""
        self.state = SessionState()
        self._cookie_jar = CookieJar()
        logger.debug("Session state reset")

    def get_state(self) -> SessionState:
        """Get the current session state"""
        return self.state

    def log_step(self, description: str):
        """Add a step to the session history"""
        self.state.history.append(description)
