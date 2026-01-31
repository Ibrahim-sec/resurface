"""
HTTP-based PoC replay engine — replays HTTP-based vulnerabilities
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
    ParsedReport, ReplayReport, ReplayResult, ReplayEvidence, PoC_Step
)


class HTTPReplayer:
    """Replays HTTP-based PoC steps against a target"""
    
    def __init__(self, timeout: int = 30, max_retries: int = 3,
                 follow_redirects: bool = True, verify_ssl: bool = True,
                 proxy: str = ""):
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.default_headers = {
            'User-Agent': 'Resurface/1.0 (Vulnerability Regression Tester)',
            'Accept': 'text/html,application/json,*/*'
        }
    
    def _execute_request(self, step: PoC_Step) -> ReplayEvidence:
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
                    # Use a custom opener that doesn't follow redirects
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
                for k, v in resp.headers.items():
                    response_log += f"{k}: {v}\n"
                response_log += f"\n{response_body[:5000]}"  # Limit response size
                evidence.response_received = response_log
                
                logger.debug(f"Step {step.order}: {method} {url} → HTTP {resp.status}")
                break
                
            except urllib.error.HTTPError as e:
                evidence.status_code = e.code
                try:
                    error_body = e.read().decode('utf-8', errors='replace')
                except:
                    error_body = str(e)
                evidence.response_received = f"HTTP {e.code}\n{error_body[:5000]}"
                logger.debug(f"Step {step.order}: {method} {url} → HTTP {e.code}")
                break
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    evidence.notes = f"Request failed after {self.max_retries} attempts: {e}"
                    logger.warning(f"Step {step.order} failed: {e}")
                else:
                    time.sleep(1)
        
        return evidence
    
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
        
        # Execute each step
        for step in sorted(parsed_report.steps, key=lambda s: s.order):
            # Apply target override if specified
            if target_override and step.url:
                original_domain = parsed_report.target_domain
                if original_domain and original_domain in step.url:
                    step.url = step.url.replace(original_domain, target_override)
                elif step.url.startswith('http'):
                    # Replace the whole domain
                    parsed_url = urllib.parse.urlparse(step.url)
                    step.url = step.url.replace(
                        f"{parsed_url.scheme}://{parsed_url.netloc}",
                        target_override.rstrip('/')
                    )
            
            evidence = self._execute_request(step)
            evidence_list.append(evidence)
            
            # Small delay between steps
            time.sleep(0.5)
        
        duration = time.time() - start_time
        
        # Build replay report (result will be determined by validator)
        report = ReplayReport(
            report_id=parsed_report.report_id,
            parsed_report=parsed_report,
            result=ReplayResult.INCONCLUSIVE,  # Validator will update this
            evidence=evidence_list,
            replayed_at=datetime.now(),
            duration_seconds=duration,
            target_url=target_override or parsed_report.target_url
        )
        
        logger.info(
            f"Replay complete for {parsed_report.report_id}: "
            f"{len(evidence_list)} steps in {duration:.1f}s"
        )
        
        return report
