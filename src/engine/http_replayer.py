"""
HTTP-based PoC replay engine — replays HTTP-based vulnerabilities

Enhanced with:
- Adaptive payload mutation (LLM-powered bypass generation)
- Session chaining (cookies, CSRF tokens, template substitution)
"""
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Optional
from datetime import datetime
from loguru import logger

from src.models import (
    ParsedReport, ReplayReport, ReplayResult, ReplayEvidence, PoC_Step,
    MutationResult, AuthEvidence,
)
from src.auth.auth_manager import AuthManager, AuthSession


class HTTPReplayer:
    """Replays HTTP-based PoC steps against a target"""

    def __init__(self, timeout: int = 30, max_retries: int = 3,
                 follow_redirects: bool = True, verify_ssl: bool = True,
                 proxy: str = "",
                 # Mutation engine options
                 mutation_engine=None,
                 enable_mutation: bool = True,
                 max_mutation_attempts: int = 5,
                 # Session manager options
                 session_manager=None,
                 enable_session: bool = True,
                 # Auth manager
                 auth_manager: AuthManager = None,
                 verbose: bool = False):
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.verbose = verbose
        self.default_headers = {
            'User-Agent': 'Resurface/1.0 (Vulnerability Regression Tester)',
            'Accept': 'text/html,application/json,*/*'
        }
        # Mutation engine (injected or None)
        self.mutation_engine = mutation_engine
        self.enable_mutation = enable_mutation
        self.max_mutation_attempts = max_mutation_attempts
        # Session manager (injected or None)
        self.session_manager = session_manager
        self.enable_session = enable_session
        # Auth manager (injected or None)
        self.auth_manager = auth_manager
        self._auth_session: Optional[AuthSession] = None

    def _inject_auth(self, headers: dict, url: str) -> str:
        """Inject auth session headers/params into a request. Returns potentially modified URL."""
        if not self._auth_session or not self._auth_session.success:
            return url
        auth_headers = self._auth_session.get_headers()
        headers.update(auth_headers)
        # Inject query param auth (api_key in param mode)
        if self._auth_session.extra_params:
            params = urllib.parse.urlencode(self._auth_session.extra_params)
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}{params}"
        return url

    def _try_reauth(self, domain: str, status_code: int) -> bool:
        """Attempt re-authentication on 401/403. Returns True if new session obtained."""
        if not self.auth_manager:
            return False
        new_session = self.auth_manager.handle_auth_failure(domain, status_code)
        if new_session and new_session.success:
            self._auth_session = new_session
            logger.info(f"🔄 Re-authenticated successfully for {domain}")
            return True
        return False

    def _execute_request(self, step: PoC_Step, target_domain: str = None) -> ReplayEvidence:
        """Execute a single HTTP request step"""
        evidence = ReplayEvidence(step_number=step.order)

        if not step.url:
            evidence.notes = "No URL specified for this step"
            return evidence

        # Build URL with params
        url = step.url
        if step.params:
            query_string = urllib.parse.urlencode(step.params)
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}{query_string}"

        # Build headers
        headers = {**self.default_headers}
        if step.headers:
            headers.update(step.headers)

        # Inject authentication headers/params
        url = self._inject_auth(headers, url)

        # Build request
        method = (step.method or 'GET').upper()
        body = None
        if step.body:
            body = step.body.encode('utf-8')
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

        # Log the request
        request_log = f"{method} {url}\n"
        for k, v in headers.items():
            request_log += f"{k}: {v}\n"
        if body:
            request_log += f"\n{body.decode('utf-8', errors='replace')}"
        evidence.request_sent = request_log

        # Execute
        for attempt in range(self.max_retries):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method=method)

                if not self.follow_redirects:
                    class NoRedirect(urllib.request.HTTPErrorProcessor):
                        def http_response(self, request, response):
                            return response
                        https_response = http_response
                    opener = urllib.request.build_opener(NoRedirect)
                    resp = opener.open(req, timeout=self.timeout)
                else:
                    resp = urllib.request.urlopen(req, timeout=self.timeout)

                # Capture response
                evidence.status_code = resp.status
                response_body = resp.read().decode('utf-8', errors='replace')

                response_log = f"HTTP {resp.status}\n"
                response_headers_str = ""
                for k, v in resp.headers.items():
                    response_log += f"{k}: {v}\n"
                    response_headers_str += f"{k}: {v}\n"
                response_log += f"\n{response_body[:5000]}"
                evidence.response_received = response_log

                # Store raw parts for mutation/session use
                evidence._response_body = response_body
                evidence._response_headers = response_headers_str

                logger.debug(f"Step {step.order}: {method} {url} → HTTP {resp.status}")
                break

            except urllib.error.HTTPError as e:
                evidence.status_code = e.code
                try:
                    error_body = e.read().decode('utf-8', errors='replace')
                except Exception:
                    error_body = str(e)

                response_headers_str = ""
                try:
                    for k, v in e.headers.items():
                        response_headers_str += f"{k}: {v}\n"
                except Exception:
                    pass

                evidence.response_received = f"HTTP {e.code}\n{response_headers_str}\n{error_body[:5000]}"
                evidence._response_body = error_body
                evidence._response_headers = response_headers_str
                logger.debug(f"Step {step.order}: {method} {url} → HTTP {e.code}")

                # Try re-auth once on 401/403, then retry this attempt
                if e.code in (401, 403) and target_domain and self._try_reauth(target_domain, e.code):
                    # Rebuild headers with new auth and retry once
                    headers = {**self.default_headers}
                    if step.headers:
                        headers.update(step.headers)
                    url_retry = step.url
                    if step.params:
                        qs = urllib.parse.urlencode(step.params)
                        sep = '&' if '?' in url_retry else '?'
                        url_retry = f"{url_retry}{sep}{qs}"
                    url_retry = self._inject_auth(headers, url_retry)
                    evidence.notes += "[re-auth attempted] "
                    try:
                        req2 = urllib.request.Request(url_retry, data=body, headers=headers, method=method)
                        resp2 = urllib.request.urlopen(req2, timeout=self.timeout)
                        evidence.status_code = resp2.status
                        rb2 = resp2.read().decode('utf-8', errors='replace')
                        rl2 = f"HTTP {resp2.status}\n"
                        for k2, v2 in resp2.headers.items():
                            rl2 += f"{k2}: {v2}\n"
                        rl2 += f"\n{rb2[:5000]}"
                        evidence.response_received = rl2
                        evidence._response_body = rb2
                        evidence.notes += "[re-auth success] "
                        logger.debug(f"Step {step.order}: re-auth retry → HTTP {resp2.status}")
                    except Exception as retry_err:
                        evidence.notes += f"[re-auth retry failed: {retry_err}] "
                break

            except Exception as e:
                if attempt == self.max_retries - 1:
                    evidence.notes = f"Request failed after {self.max_retries} attempts: {e}"
                    evidence._response_body = ""
                    evidence._response_headers = ""
                    logger.warning(f"Step {step.order} failed: {e}")
                else:
                    time.sleep(1)

        return evidence

    def _make_mutation_replay_fn(self, step: PoC_Step):
        """
        Create a replay function that the mutation engine can call to test
        mutated payloads. Returns a callable(payload) -> (status_code, body).
        """
        def replay_fn(mutated_payload: str) -> tuple[Optional[int], str]:
            """Test a mutated payload by re-executing the step with the new payload"""
            import copy
            mutated_step = copy.deepcopy(step)

            # Inject the mutated payload into the step
            if mutated_step.payload:
                # Replace the original payload everywhere it appears
                original = mutated_step.payload
                if mutated_step.url and original in mutated_step.url:
                    mutated_step.url = mutated_step.url.replace(original, mutated_payload)
                if mutated_step.body and original in mutated_step.body:
                    mutated_step.body = mutated_step.body.replace(original, mutated_payload)
                for k, v in list(mutated_step.params.items()):
                    if isinstance(v, str) and original in v:
                        mutated_step.params[k] = v.replace(original, mutated_payload)
                mutated_step.payload = mutated_payload
            else:
                # No explicit payload field — try URL params and body
                if mutated_step.body:
                    mutated_step.body = mutated_payload
                elif mutated_step.params:
                    # Replace the last param value (likely the payload)
                    last_key = list(mutated_step.params.keys())[-1]
                    mutated_step.params[last_key] = mutated_payload
                elif mutated_step.url:
                    # Append to URL
                    sep = '&' if '?' in mutated_step.url else '?'
                    mutated_step.url += f"{sep}payload={urllib.parse.quote(mutated_payload)}"

            evidence = self._execute_request(mutated_step)
            body = getattr(evidence, '_response_body', '') or ''
            return evidence.status_code, body

        return replay_fn

    def replay(self, parsed_report: ParsedReport,
               target_override: str = None) -> ReplayReport:
        """
        Replay all HTTP steps from a parsed report.

        Args:
            parsed_report: The LLM-parsed report with PoC steps
            target_override: Override the target URL (for testing against your own app)

        Returns:
            ReplayReport with results and evidence
        """
        start_time = time.time()
        logger.info(f"Replaying report {parsed_report.report_id}: {parsed_report.title[:50]}")

        evidence_list = []
        mutation_results = []
        auth_evidence = None

        # Authenticate if needed
        if self.auth_manager and parsed_report.requires_auth:
            domain = parsed_report.target_domain or ''
            logger.info(f"🔑 Report requires auth — authenticating for domain: {domain}")
            self._auth_session = self.auth_manager.authenticate(domain)
            if self._auth_session:
                auth_evidence = AuthEvidence(
                    profile_name=self._auth_session.profile_name,
                    auth_type=self._auth_session.auth_type.value,
                    success=self._auth_session.success,
                    log=self._auth_session.log,
                    timestamp=datetime.now(),
                )
                if self._auth_session.success:
                    logger.info(f"✅ Auth session ready for replay")
                else:
                    logger.warning(f"⚠️ Auth failed, continuing without auth")
            else:
                logger.info(f"ℹ️ No auth profile for domain '{domain}', proceeding without auth")

        # Reset session manager if present
        if self.session_manager and self.enable_session:
            self.session_manager.reset()
            logger.info("  🔗 Session chaining enabled")

        # Execute each step
        for step in sorted(parsed_report.steps, key=lambda s: s.order):
            # Apply target override if specified
            if target_override and step.url:
                # Skip if URL already points to the target
                target_clean = target_override.rstrip('/')
                parsed_target = urllib.parse.urlparse(target_clean)
                parsed_step = urllib.parse.urlparse(step.url)
                target_netloc = parsed_target.netloc or parsed_target.path
                
                if parsed_step.netloc and target_netloc and parsed_step.netloc == target_netloc:
                    # URL already points to the right target — no replacement needed
                    pass
                else:
                    original_domain = parsed_report.target_domain
                    if original_domain and original_domain in step.url:
                        # Replace domain, but avoid double-protocol issues
                        parsed_url = urllib.parse.urlparse(step.url)
                        step.url = f"{target_clean}{parsed_url.path}"
                        if parsed_url.query:
                            step.url += f"?{parsed_url.query}"
                        if parsed_url.fragment:
                            step.url += f"#{parsed_url.fragment}"
                    elif step.url.startswith('http'):
                        parsed_url = urllib.parse.urlparse(step.url)
                        step.url = f"{target_clean}{parsed_url.path}"
                        if parsed_url.query:
                            step.url += f"?{parsed_url.query}"
                        if parsed_url.fragment:
                            step.url += f"#{parsed_url.fragment}"

            # Apply session state (template substitution, cookies)
            if self.session_manager and self.enable_session:
                self.session_manager.apply_to_step(step)

            # Execute the step (pass domain for potential re-auth on 401/403)
            evidence = self._execute_request(step, target_domain=parsed_report.target_domain)
            evidence_list.append(evidence)

            # Extract session values from response
            if self.session_manager and self.enable_session:
                response_body = getattr(evidence, '_response_body', '') or ''
                response_headers = getattr(evidence, '_response_headers', '') or ''
                request_summary = evidence.request_sent or ''
                self.session_manager.extract_values_from_response(
                    request_summary=request_summary,
                    status_code=evidence.status_code,
                    response_headers=response_headers,
                    response_body=response_body,
                )
                self.session_manager.log_step(
                    f"Step {step.order}: {step.method or 'GET'} {step.url} → {evidence.status_code}"
                )

            # Check if payload was blocked and try mutation
            if (
                self.mutation_engine
                and self.enable_mutation
                and step.payload
            ):
                response_body = getattr(evidence, '_response_body', '') or ''
                response_headers = getattr(evidence, '_response_headers', '') or ''

                mutation_result = self.mutation_engine.check_and_mutate(
                    payload=step.payload,
                    vuln_type=parsed_report.vuln_type.value,
                    request_summary=evidence.request_sent or '',
                    status_code=evidence.status_code,
                    response_body=response_body,
                    response_headers=response_headers,
                    replay_fn=self._make_mutation_replay_fn(step),
                    max_attempts=self.max_mutation_attempts,
                )

                if mutation_result:
                    mutation_results.append(mutation_result)

                    # Add mutation attempts as evidence
                    for attempt in mutation_result.attempts:
                        mut_evidence = ReplayEvidence(
                            step_number=step.order,
                            request_sent=f"MUTATION [{attempt.strategy}]: {attempt.mutated_payload[:200]}",
                            response_received=attempt.response_snippet[:2000],
                            status_code=attempt.status_code,
                            notes=(
                                f"Mutation attempt {attempt.attempt_number}: "
                                f"{'BYPASS' if attempt.success else 'BLOCKED'} | "
                                f"{attempt.rationale}"
                            ),
                        )
                        evidence_list.append(mut_evidence)

                    # If bypass found, update the evidence
                    if mutation_result.bypassed and mutation_result.final_payload:
                        evidence.notes += (
                            f" | ✅ BYPASS FOUND: {mutation_result.final_payload[:100]}"
                        )

            # Small delay between steps
            time.sleep(0.5)

        duration = time.time() - start_time

        # Build replay report
        report = ReplayReport(
            report_id=parsed_report.report_id,
            parsed_report=parsed_report,
            result=ReplayResult.INCONCLUSIVE,  # Validator will update this
            evidence=evidence_list,
            auth_evidence=auth_evidence,
            replayed_at=datetime.now(),
            duration_seconds=duration,
            target_url=target_override or parsed_report.target_url,
            mutation_results=mutation_results,
            session_state=(
                self.session_manager.get_state()
                if self.session_manager and self.enable_session
                else None
            ),
        )

        logger.info(
            f"Replay complete for {parsed_report.report_id}: "
            f"{len(evidence_list)} steps in {duration:.1f}s"
            + (f", {len(mutation_results)} mutation rounds" if mutation_results else "")
        )

        return report
