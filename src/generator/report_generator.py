"""
ReportGenerator — crawl a target URL and auto-generate vulnerability report
JSON files that match the existing Resurface report format.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Weakness catalogue (subset used for auto-generation)
# ---------------------------------------------------------------------------
WEAKNESS_MAP: dict[str, dict[str, Any]] = {
    "xss_reflected": {
        "id": 61,
        "name": "Cross-site Scripting (XSS) - Reflected",
        "severity": "medium",
        "difficulty": "easy",
    },
    "sqli": {
        "id": 67,
        "name": "SQL Injection",
        "severity": "critical",
        "difficulty": "medium",
    },
    "idor": {
        "id": 55,
        "name": "Insecure Direct Object Reference (IDOR)",
        "severity": "high",
        "difficulty": "easy",
    },
    "privilege_escalation": {
        "id": 75,
        "name": "Privilege Escalation",
        "severity": "critical",
        "difficulty": "easy",
    },
    "info_disclosure": {
        "id": 18,
        "name": "Information Disclosure",
        "severity": "low",
        "difficulty": "easy",
    },
}

DEFAULT_VULN_TYPES = list(WEAKNESS_MAP.keys())

# ---------------------------------------------------------------------------
# Vulnerability-information templates (Markdown)
# ---------------------------------------------------------------------------

_XSS_TEMPLATE = """\
## Summary
The endpoint `{endpoint}` reflects user-supplied input from the `{param}` \
parameter directly into the HTML response without adequate sanitisation, \
enabling Reflected Cross-Site Scripting.

## Steps to Reproduce
1. Navigate to `{target_url}`.
2. Locate the form at **{form_action}** (method: {form_method}).
3. Enter the following payload in the **{param}** field:
```
<img src=x onerror=alert(document.domain)>
```
4. Submit the form.
5. Observe JavaScript execution in the browser context.

## Impact
An attacker can craft a malicious link that, when visited by a victim, \
executes arbitrary JavaScript in their browser session — enabling session \
hijacking, credential theft, and phishing overlays.

## Remediation
HTML-encode all user-controlled values before rendering them in the DOM."""

_SQLI_TEMPLATE = """\
## Summary
The `{param}` parameter at `{endpoint}` is susceptible to SQL Injection. \
Unsanitised input is concatenated into a backend SQL query, allowing an \
attacker to read, modify, or delete database contents.

## Steps to Reproduce
1. Navigate to `{target_url}`.
2. Locate the form at **{form_action}** (method: {form_method}).
3. In the **{param}** field, enter:
```
' OR 1=1 --
```
4. Submit the form.
5. Observe that the application returns data for all records, confirming \
the injection.

### Time-based confirmation
```
' OR IF(1=1, SLEEP(5), 0) --
```
A 5-second delay confirms blind SQL injection.

## Impact
Critical — full database compromise, including user credentials and \
personally identifiable information.

## Remediation
Use parameterised queries / prepared statements for all database access."""

_IDOR_TEMPLATE = """\
## Summary
The API endpoint `{endpoint}` is vulnerable to Insecure Direct Object \
Reference (IDOR). Sequential or predictable resource identifiers are \
accepted without authorisation checks, allowing access to other users' data.

## Steps to Reproduce
1. Authenticate as a low-privilege user on `{target_url}`.
2. Send a request to the endpoint:
```
GET {endpoint}/1
Authorization: Bearer <low_priv_token>
```
3. Increment the ID:
```
GET {endpoint}/2
```
4. Observe that the response contains another user's data.

## Impact
High — any authenticated user can enumerate and access resources belonging \
to other users, violating data confidentiality.

## Remediation
Implement server-side authorisation checks that verify the requesting user \
owns the resource before returning data."""

_PRIVESC_TEMPLATE = """\
## Summary
The endpoint `{endpoint}` does not properly validate role or privilege \
fields in the request body. An attacker can inject elevated roles during \
user creation or profile update.

## Steps to Reproduce
1. Intercept or craft a request to `{endpoint}`:
```
POST {endpoint}
Content-Type: application/json

{{
  "email": "attacker@evil.com",
  "password": "P@ssw0rd!",
  "role": "admin"
}}
```
2. The server accepts the `role` field without validation.
3. Log in with the new account and confirm administrative privileges.

## Impact
Critical — unauthenticated or low-privilege users can escalate to admin, \
fully compromising application security controls.

## Remediation
Ignore or reject client-supplied role/privilege fields. Assign roles \
exclusively on the server side based on business logic."""

_INFO_DISCLOSURE_TEMPLATE = """\
## Summary
The page at `{endpoint}` exposes sensitive technical information including \
server software versions, internal paths, or stack traces that could aid \
an attacker in further exploitation.

## Steps to Reproduce
1. Navigate to `{target_url}`.
2. Request the endpoint:
```
GET {endpoint}
```
3. Inspect the response headers and body for information such as:
   - Server version headers (e.g., `X-Powered-By`, `Server`)
   - Internal file paths
   - Debugging / stack trace output

## Impact
Low — information leakage reduces the effort required to craft targeted \
attacks against known software versions.

## Remediation
Remove verbose error pages in production, strip server identification \
headers, and disable debug modes."""

VULN_TEMPLATES: dict[str, str] = {
    "xss_reflected": _XSS_TEMPLATE,
    "sqli": _SQLI_TEMPLATE,
    "idor": _IDOR_TEMPLATE,
    "privilege_escalation": _PRIVESC_TEMPLATE,
    "info_disclosure": _INFO_DISCLOSURE_TEMPLATE,
}


# ---------------------------------------------------------------------------
# Helper: decide which vuln types apply to a given form / endpoint
# ---------------------------------------------------------------------------

def _applicable_vulns(
    form: dict | None = None,
    endpoint: str | None = None,
    vuln_types: list[str] | None = None,
) -> list[str]:
    """Return the subset of *vuln_types* that make sense for the given context."""
    candidates = vuln_types or DEFAULT_VULN_TYPES
    applicable: list[str] = []

    if form:
        method = (form.get("method") or "get").lower()
        inputs = [i.get("name", "").lower() for i in form.get("inputs", [])]
        has_text_input = any(
            i.get("type", "text") in ("text", "search", "email", "password", "textarea", "hidden")
            for i in form.get("inputs", [])
        )

        if has_text_input and "xss_reflected" in candidates:
            applicable.append("xss_reflected")

        # SQLi likely on login/search forms
        login_signals = {"username", "user", "email", "password", "login", "search", "query", "q"}
        if has_text_input and login_signals & set(inputs) and "sqli" in candidates:
            applicable.append("sqli")

        if method == "post" and "privilege_escalation" in candidates:
            applicable.append("privilege_escalation")

    if endpoint:
        # IDOR for REST-style /api/… paths
        if re.search(r"/api/", endpoint, re.IGNORECASE) and "idor" in candidates:
            applicable.append("idor")

        # info_disclosure for any endpoint
        if "info_disclosure" in candidates:
            applicable.append("info_disclosure")

    # deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for v in applicable:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Crawl a target and auto-generate Resurface-format vulnerability reports."""

    def __init__(self, output_dir: str = "data/reports", verbose: bool = False) -> None:
        self.output_dir = output_dir
        self.verbose = verbose
        os.makedirs(self.output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Crawl
    # ------------------------------------------------------------------

    def crawl_target(self, url: str) -> dict:
        """Crawl *url*, returning a site-map dictionary.

        Returns
        -------
        dict with keys ``forms``, ``inputs``, ``links``, ``api_endpoints``.
        """
        parsed_base = urlparse(url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        forms: list[dict] = []
        all_inputs: list[dict] = []
        links: list[str] = []
        api_endpoints: list[str] = []
        visited: set[str] = set()
        to_visit: list[str] = [url]

        client = httpx.Client(
            timeout=15,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "ResurfaceGenerator/1.0"},
        )

        max_pages = 50  # safety cap

        try:
            while to_visit and len(visited) < max_pages:
                current = to_visit.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                if self.verbose:
                    print(f"[crawl] {current}")

                try:
                    resp = client.get(current)
                except httpx.HTTPError as exc:
                    if self.verbose:
                        print(f"[crawl] error fetching {current}: {exc}")
                    continue

                content_type = resp.headers.get("content-type", "")
                if "html" not in content_type and "json" not in content_type:
                    continue

                # ----- JSON / API discovery -----
                if "json" in content_type:
                    api_endpoints.append(current)
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            # Swagger/OpenAPI auto-detect
                            if "paths" in data or "openapi" in data or "swagger" in data:
                                for path in data.get("paths", {}):
                                    full = urljoin(base_origin, path)
                                    api_endpoints.append(full)
                    except Exception:
                        pass
                    continue

                # ----- HTML parsing -----
                soup = BeautifulSoup(resp.text, "html.parser")

                # Forms
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "")
                    abs_action = urljoin(current, action) if action else current
                    method = (form_tag.get("method") or "GET").upper()
                    input_list: list[dict] = []
                    for inp in form_tag.find_all(["input", "textarea", "select"]):
                        input_list.append({
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "tag": inp.name,
                        })
                        all_inputs.append({
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "tag": inp.name,
                            "form_action": abs_action,
                        })
                    forms.append({
                        "action": abs_action,
                        "method": method,
                        "inputs": input_list,
                        "page": current,
                    })

                # Links
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    abs_href = urljoin(current, href)
                    parsed_href = urlparse(abs_href)

                    # stay same-origin
                    if parsed_href.netloc and parsed_href.netloc != parsed_base.netloc:
                        continue

                    clean = abs_href.split("#")[0].split("?")[0]
                    if clean and clean not in visited:
                        links.append(abs_href)
                        to_visit.append(abs_href)

                    # heuristic: /api/ or /rest/ → API endpoint
                    if re.search(r"/(api|rest|graphql|v\d)/", abs_href, re.IGNORECASE):
                        api_endpoints.append(abs_href)

                # Script-src based API discovery
                for script in soup.find_all("script", src=True):
                    src = urljoin(current, script["src"])
                    if re.search(r"/(api|rest)/", src, re.IGNORECASE):
                        api_endpoints.append(src)

        finally:
            client.close()

        # deduplicate
        links = list(dict.fromkeys(links))
        api_endpoints = list(dict.fromkeys(api_endpoints))

        site_map = {
            "forms": forms,
            "inputs": all_inputs,
            "links": links,
            "api_endpoints": api_endpoints,
        }

        if self.verbose:
            print(
                f"[crawl] done — {len(forms)} forms, {len(all_inputs)} inputs, "
                f"{len(links)} links, {len(api_endpoints)} API endpoints"
            )

        return site_map

    # ------------------------------------------------------------------
    # Report generation from crawl
    # ------------------------------------------------------------------

    def generate_reports(
        self,
        url: str,
        vuln_types: list[str] | None = None,
        start_id: int = 990001,
    ) -> list[dict]:
        """Crawl *url* and auto-generate report stubs.

        Parameters
        ----------
        url:
            Target base URL to crawl.
        vuln_types:
            Vulnerability classes to consider.  Defaults to all five built-in
            types (xss_reflected, sqli, idor, privilege_escalation,
            info_disclosure).
        start_id:
            First numeric report ID to assign.

        Returns
        -------
        list of generated report dicts (also saved as JSON files).
        """
        vuln_types = vuln_types or DEFAULT_VULN_TYPES
        site_map = self.crawl_target(url)

        reports: list[dict] = []
        current_id = start_id
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # --- From forms ---
        for form in site_map["forms"]:
            applicable = _applicable_vulns(form=form, vuln_types=vuln_types)
            for vtype in applicable:
                weakness = WEAKNESS_MAP[vtype]
                template = VULN_TEMPLATES[vtype]

                # Pick a representative param name
                param_name = next(
                    (i["name"] for i in form.get("inputs", []) if i.get("name")),
                    "input",
                )

                vuln_info = template.format(
                    endpoint=form["action"],
                    param=param_name,
                    target_url=url,
                    form_action=form["action"],
                    form_method=form["method"],
                )

                report = self._build_report(
                    report_id=current_id,
                    title=f"{weakness['name']} in {form['action']}",
                    severity=weakness["severity"],
                    weakness_id=weakness["id"],
                    weakness_name=weakness["name"],
                    vuln_info=vuln_info,
                    difficulty=weakness["difficulty"],
                    target_url=url,
                    disclosed_at=now_iso,
                )
                self._save_report(report)
                reports.append(report)
                current_id += 1

        # --- From API endpoints (IDOR / info_disclosure) ---
        for ep in site_map["api_endpoints"]:
            applicable = _applicable_vulns(endpoint=ep, vuln_types=vuln_types)
            for vtype in applicable:
                weakness = WEAKNESS_MAP[vtype]
                template = VULN_TEMPLATES[vtype]

                vuln_info = template.format(
                    endpoint=ep,
                    param="id",
                    target_url=url,
                    form_action=ep,
                    form_method="GET",
                )

                report = self._build_report(
                    report_id=current_id,
                    title=f"{weakness['name']} at {ep}",
                    severity=weakness["severity"],
                    weakness_id=weakness["id"],
                    weakness_name=weakness["name"],
                    vuln_info=vuln_info,
                    difficulty=weakness["difficulty"],
                    target_url=url,
                    disclosed_at=now_iso,
                )
                self._save_report(report)
                reports.append(report)
                current_id += 1

        if self.verbose:
            print(f"[generate] {len(reports)} reports written to {self.output_dir}/")

        return reports

    # ------------------------------------------------------------------
    # Report generation from OpenAPI / Swagger spec
    # ------------------------------------------------------------------

    def generate_from_openapi(
        self,
        spec_url: str,
        start_id: int = 990001,
    ) -> list[dict]:
        """Parse an OpenAPI/Swagger spec and generate reports for each endpoint.

        Parameters
        ----------
        spec_url:
            URL (or local path served over HTTP) pointing to a JSON or YAML
            OpenAPI specification.
        start_id:
            First numeric report ID.

        Returns
        -------
        list of generated report dicts.
        """
        client = httpx.Client(timeout=15, follow_redirects=True, verify=False)
        try:
            resp = client.get(spec_url)
            resp.raise_for_status()
            spec = resp.json()
        finally:
            client.close()

        # Determine base URL from spec
        base_url = spec_url.rsplit("/", 1)[0]
        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            base_url = servers[0].get("url", base_url)
        elif "host" in spec:  # Swagger 2.0
            scheme = (spec.get("schemes") or ["https"])[0]
            base_path = spec.get("basePath", "")
            base_url = f"{scheme}://{spec['host']}{base_path}"

        paths: dict = spec.get("paths", {})
        reports: list[dict] = []
        current_id = start_id
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            full_endpoint = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            for method, details in methods.items():
                if method.lower() in ("parameters", "summary", "description", "servers"):
                    continue  # skip non-method keys

                method_upper = method.upper()

                # Determine which vuln types apply
                vtypes: list[str] = []
                if method_upper in ("POST", "PUT", "PATCH"):
                    vtypes.extend(["sqli", "xss_reflected", "privilege_escalation"])
                if method_upper == "GET":
                    vtypes.extend(["idor", "info_disclosure", "xss_reflected"])
                if "{" in path:
                    if "idor" not in vtypes:
                        vtypes.append("idor")

                # Pick a representative parameter name
                params = details.get("parameters", [])
                param_name = "id"
                for p in params:
                    if isinstance(p, dict) and p.get("name"):
                        param_name = p["name"]
                        break

                for vtype in vtypes:
                    if vtype not in WEAKNESS_MAP:
                        continue
                    weakness = WEAKNESS_MAP[vtype]
                    template = VULN_TEMPLATES[vtype]

                    vuln_info = template.format(
                        endpoint=full_endpoint,
                        param=param_name,
                        target_url=base_url,
                        form_action=full_endpoint,
                        form_method=method_upper,
                    )

                    summary = ""
                    if isinstance(details, dict):
                        summary = details.get("summary", "") or details.get("operationId", "")

                    title_suffix = f" ({summary})" if summary else ""
                    report = self._build_report(
                        report_id=current_id,
                        title=f"{weakness['name']} via {method_upper} {path}{title_suffix}",
                        severity=weakness["severity"],
                        weakness_id=weakness["id"],
                        weakness_name=weakness["name"],
                        vuln_info=vuln_info,
                        difficulty=weakness["difficulty"],
                        target_url=base_url,
                        disclosed_at=now_iso,
                    )
                    self._save_report(report)
                    reports.append(report)
                    current_id += 1

        if self.verbose:
            print(
                f"[openapi] {len(reports)} reports generated from "
                f"{len(paths)} paths in {spec_url}"
            )

        return reports

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_report(
        *,
        report_id: int,
        title: str,
        severity: str,
        weakness_id: int,
        weakness_name: str,
        vuln_info: str,
        difficulty: str,
        target_url: str,
        disclosed_at: str,
    ) -> dict:
        return {
            "id": report_id,
            "title": title,
            "severity_rating": severity,
            "state": "disclosed",
            "substate": "resolved",
            "visibility": "full",
            "disclosed_at": disclosed_at,
            "team": {
                "handle": "auto-generated",
                "name": "Auto-Generated",
            },
            "reporter": {
                "username": "resurface_generator",
            },
            "weakness": {
                "id": weakness_id,
                "name": weakness_name,
            },
            "vulnerability_information": vuln_info,
            "difficulty": difficulty,
            "target_url": target_url,
        }

    def _save_report(self, report: dict) -> str:
        """Write *report* to a JSON file and return the file path."""
        path = os.path.join(self.output_dir, f"{report['id']}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        if self.verbose:
            print(f"[save] {path}")
        return path
