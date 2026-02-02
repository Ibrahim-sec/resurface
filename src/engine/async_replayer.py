"""
Async HTTP-based PoC replay engine — concurrent replay of multiple reports.

Uses asyncio + httpx.AsyncClient for parallel execution with:
- Configurable concurrency (semaphore-based)
- Shared rate limiter to respect target rate limits
- Progress tracking (report X of Y, ETA)
- Results returned as they complete
"""
import asyncio
import time
import urllib.parse
from typing import Optional, Callable
from datetime import datetime

import httpx
from loguru import logger

from src.models import (
    ParsedReport, ReplayReport, ReplayResult, ReplayEvidence, PoC_Step
)


class AsyncRateLimiter:
    """Token-bucket rate limiter for async context."""

    def __init__(self, rate: float = 10.0, burst: int = 5):
        """
        Args:
            rate: Requests per second allowed.
            burst: Maximum burst size.
        """
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until a token is available."""
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

            # Wait a bit and retry
            await asyncio.sleep(1.0 / self.rate)


class ProgressTracker:
    """Track progress of concurrent replay tasks."""

    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.start_time = time.monotonic()
        self._lock = asyncio.Lock()

    async def tick(self, report_id, status: str):
        async with self._lock:
            self.completed += 1
            elapsed = time.monotonic() - self.start_time
            if self.completed > 0 and self.completed < self.total:
                avg = elapsed / self.completed
                remaining = avg * (self.total - self.completed)
                eta_str = f"{remaining:.0f}s remaining"
            else:
                eta_str = "done" if self.completed >= self.total else "calculating..."

            logger.info(
                f"[{self.completed}/{self.total}] Report #{report_id}: "
                f"{status} ({eta_str})"
            )

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time


class AsyncHTTPReplayer:
    """Replays HTTP-based PoC steps using async httpx."""

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        concurrency: int = 5,
        rate_limit: float = 10.0,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.concurrency = concurrency
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit, burst=concurrency)
        self.default_headers = {
            'User-Agent': 'Resurface/1.0 (Vulnerability Regression Tester)',
            'Accept': 'text/html,application/json,*/*'
        }

    async def _execute_request(
        self, client: httpx.AsyncClient, step: PoC_Step
    ) -> ReplayEvidence:
        """Execute a single HTTP request step."""
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

        # Method and body
        method = (step.method or 'GET').upper()
        body = None
        if step.body:
            body = step.body.encode('utf-8')
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

        # Log request
        request_log = f"{method} {url}\n"
        for k, v in headers.items():
            request_log += f"{k}: {v}\n"
        if body:
            request_log += f"\n{body.decode('utf-8', errors='replace')}"
        evidence.request_sent = request_log

        # Execute with retries
        for attempt in range(self.max_retries):
            try:
                await self.rate_limiter.acquire()

                resp = await client.request(
                    method, url,
                    headers=headers,
                    content=body,
                    timeout=self.timeout,
                    follow_redirects=self.follow_redirects,
                )

                evidence.status_code = resp.status_code
                response_body = resp.text[:5000]

                response_log = f"HTTP {resp.status_code}\n"
                for k, v in resp.headers.items():
                    response_log += f"{k}: {v}\n"
                response_log += f"\n{response_body}"
                evidence.response_received = response_log

                logger.debug(
                    f"Step {step.order}: {method} {url} → HTTP {resp.status_code}"
                )
                break

            except httpx.HTTPStatusError as e:
                evidence.status_code = e.response.status_code
                evidence.response_received = f"HTTP {e.response.status_code}\n{e.response.text[:5000]}"
                break

            except Exception as e:
                if attempt == self.max_retries - 1:
                    evidence.notes = f"Request failed after {self.max_retries} attempts: {e}"
                    logger.warning(f"Step {step.order} failed: {e}")
                else:
                    await asyncio.sleep(1)

        return evidence

    async def replay_one(
        self,
        client: httpx.AsyncClient,
        parsed_report: ParsedReport,
        target_override: str = None,
    ) -> ReplayReport:
        """Replay all HTTP steps from a single parsed report."""
        start_time = time.time()
        logger.info(
            f"Replaying report {parsed_report.report_id}: "
            f"{parsed_report.title[:50]}"
        )

        evidence_list = []

        for step in sorted(parsed_report.steps, key=lambda s: s.order):
            # Apply target override
            if target_override and step.url:
                original_domain = parsed_report.target_domain
                if original_domain and original_domain in step.url:
                    step.url = step.url.replace(original_domain, target_override)
                elif step.url.startswith('http'):
                    parsed_url = urllib.parse.urlparse(step.url)
                    step.url = step.url.replace(
                        f"{parsed_url.scheme}://{parsed_url.netloc}",
                        target_override.rstrip('/')
                    )

            evidence = await self._execute_request(client, step)
            evidence_list.append(evidence)

            # Small delay between steps within one report
            await asyncio.sleep(0.3)

        duration = time.time() - start_time

        report = ReplayReport(
            report_id=parsed_report.report_id,
            parsed_report=parsed_report,
            result=ReplayResult.INCONCLUSIVE,
            evidence=evidence_list,
            replayed_at=datetime.now(),
            duration_seconds=duration,
            target_url=target_override or parsed_report.target_url,
        )

        logger.info(
            f"Replay complete for {parsed_report.report_id}: "
            f"{len(evidence_list)} steps in {duration:.1f}s"
        )
        return report

    async def replay_batch(
        self,
        parsed_reports: list[ParsedReport],
        target_override: str = None,
        on_result: Optional[Callable] = None,
    ) -> list[ReplayReport]:
        """
        Replay multiple reports concurrently.

        Args:
            parsed_reports: List of ParsedReport objects.
            target_override: Target URL override for all reports.
            on_result: Optional callback(ReplayReport) called as each completes.

        Returns:
            List of ReplayReport results.
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        progress = ProgressTracker(total=len(parsed_reports))
        results: list[ReplayReport] = []
        results_lock = asyncio.Lock()

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
        ) as client:

            async def _run_one(parsed_report: ParsedReport):
                async with semaphore:
                    try:
                        result = await self.replay_one(
                            client, parsed_report, target_override
                        )
                        status = "completed"
                    except Exception as e:
                        logger.error(
                            f"Replay failed for {parsed_report.report_id}: {e}"
                        )
                        result = ReplayReport(
                            report_id=parsed_report.report_id,
                            parsed_report=parsed_report,
                            result=ReplayResult.ERROR,
                            error_message=str(e),
                            replayed_at=datetime.now(),
                            duration_seconds=0.0,
                            target_url=target_override,
                        )
                        status = "error"

                    async with results_lock:
                        results.append(result)

                    await progress.tick(parsed_report.report_id, status)

                    if on_result:
                        try:
                            on_result(result)
                        except Exception as e:
                            logger.warning(f"on_result callback error: {e}")

            tasks = [_run_one(pr) for pr in parsed_reports]
            await asyncio.gather(*tasks)

        total_time = progress.elapsed
        logger.info(
            f"Batch replay complete: {len(results)} reports in {total_time:.1f}s "
            f"(concurrency={self.concurrency})"
        )
        return results
