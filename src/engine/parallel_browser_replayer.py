"""
Parallel Browser Replay — run multiple BrowserUseReplayer instances concurrently.

Each report gets its own browser instance and agent.
Uses asyncio.Semaphore for concurrency control so we don't OOM the host
(each Chrome instance uses ~200-300 MB RAM).
"""

import asyncio
import time
from typing import Optional
from pathlib import Path
from loguru import logger

# Project-level imports
from src.models import ParsedReport, ReplayReport, ReplayResult


class ParallelBrowserReplayer:
    """
    Runs multiple BrowserUseReplayer instances concurrently.
    Each report gets its own browser instance and agent.
    Uses asyncio.Semaphore for concurrency control.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-0",
        provider: str = "claude",
        headless: bool = True,
        auth_manager=None,
        verbose: bool = False,
        evidence_dir: str = "data/results",
        blind: bool = False,
        max_actions: int = 15,
        concurrency: int = 3,  # Max simultaneous browser instances
        groq_api_key: str = None,
        claude_api_key: str = None,
        use_cloud: bool = False,
    ):
        self.concurrency = concurrency
        # Store all params to create BrowserUseReplayer instances
        self.replayer_kwargs = {
            "api_key": api_key,
            "model": model,
            "provider": provider,
            "headless": headless,
            "auth_manager": auth_manager,
            "verbose": verbose,
            "evidence_dir": evidence_dir,
            "blind": blind,
            "max_actions": max_actions,
            "groq_api_key": groq_api_key,
            "claude_api_key": claude_api_key,
            "use_cloud": use_cloud,
        }

    async def _replay_one(
        self,
        semaphore: asyncio.Semaphore,
        report: ParsedReport,
        target: str,
        index: int,
        total: int,
    ) -> ReplayReport:
        """Replay a single report within the semaphore limit."""
        async with semaphore:
            logger.info(
                f"  [{index}/{total}] Starting: {report.title[:50]} "
                f"(report {report.report_id})"
            )
            start = time.time()

            try:
                # Create a fresh replayer instance for this report (own browser)
                from src.browser.browseruse_replayer import BrowserUseReplayer

                replayer = BrowserUseReplayer(**self.replayer_kwargs)
                result = await replayer._async_replay(
                    report, target_override=target
                )

                dur = time.time() - start
                emoji = {
                    "vulnerable": "🔴",
                    "fixed": "🟢",
                    "partial": "🟡",
                    "inconclusive": "⚪",
                    "error": "❌",
                }.get(result.result.value, "?")
                logger.info(
                    f"  [{index}/{total}] {emoji} {result.result.value.upper()} "
                    f"({result.confidence:.0%}) — {report.report_id} in {dur:.1f}s"
                )
                return result

            except Exception as e:
                dur = time.time() - start
                logger.error(
                    f"  [{index}/{total}] ❌ Error: {report.report_id} — {e}"
                )
                from datetime import datetime

                return ReplayReport(
                    report_id=report.report_id,
                    parsed_report=report,
                    result=ReplayResult.ERROR,
                    confidence=0.0,
                    evidence=[],
                    replayed_at=datetime.now(),
                    duration_seconds=dur,
                    target_url=target,
                    error_message=str(e),
                )

    async def replay_batch_async(
        self, reports: list[ParsedReport], target: str
    ) -> list[ReplayReport]:
        """
        Replay multiple reports in parallel.

        Args:
            reports: List of parsed reports to replay.
            target: Target URL.

        Returns:
            List of ReplayReport results (same order as input).
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        total = len(reports)

        logger.info(
            f"⚡ Parallel replay: {total} reports, concurrency={self.concurrency}"
        )
        start = time.time()

        tasks = [
            self._replay_one(semaphore, report, target, i + 1, total)
            for i, report in enumerate(reports)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert any bare exceptions to error reports
        final_results: list[ReplayReport] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                from datetime import datetime

                final_results.append(
                    ReplayReport(
                        report_id=reports[i].report_id,
                        parsed_report=reports[i],
                        result=ReplayResult.ERROR,
                        confidence=0.0,
                        evidence=[],
                        replayed_at=datetime.now(),
                        duration_seconds=0.0,
                        target_url=target,
                        error_message=str(result),
                    )
                )
            else:
                final_results.append(result)

        dur = time.time() - start

        # Summary
        vuln = sum(
            1 for r in final_results if r.result == ReplayResult.VULNERABLE
        )
        fixed = sum(
            1 for r in final_results if r.result == ReplayResult.FIXED
        )
        errors = sum(
            1 for r in final_results if r.result == ReplayResult.ERROR
        )
        logger.info(
            f"⚡ Parallel replay complete: {total} reports in {dur:.1f}s "
            f"({vuln} vulnerable, {fixed} fixed, {errors} errors)"
        )

        return final_results

    def replay_batch(
        self, reports: list[ParsedReport], target: str
    ) -> list[ReplayReport]:
        """Sync wrapper for replay_batch_async."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # We're inside an existing event loop (e.g. Jupyter, nested call).
            # Spin up a new thread so asyncio.run() gets its own loop.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run, self.replay_batch_async(reports, target)
                ).result()

        return asyncio.run(self.replay_batch_async(reports, target))
