"""
LLM-powered report parser — extracts structured PoC steps from raw reports.

Uses instructor for guaranteed Pydantic structured output.
"""
from typing import Optional
from datetime import datetime
from loguru import logger

from src.models import (
    ParsedReport, PoC_Step, VulnType, ReplayMethod, LLMParsedReport
)
from src.llm import LLMClient
from src.prompts import load_prompt, format_prompt


class LLMParser:
    """Parses bug bounty reports using LLM with structured output."""
    
    def __init__(
        self,
        api_key: str,
        model: str = "llama-4-scout-17b-16e-instruct",
        temperature: float = 0.1,
        provider: str = "groq",
        verbose: bool = False,
    ):
        self.client = LLMClient(
            api_key=api_key,
            model=model,
            provider=provider,
            temperature=temperature,
            max_tokens=4096,
            verbose=verbose,
        )
        self.verbose = verbose
    
    def parse_report(self, report: dict) -> Optional[ParsedReport]:
        """
        Parse a raw HackerOne report into structured PoC steps.
        
        Uses instructor for guaranteed valid Pydantic output.
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
        
        # Load and format prompt template
        prompt = format_prompt(
            "parse_report",
            title=title,
            team=team,
            severity=severity,
            weakness=weakness_name,
            vulnerability_information=vuln_info[:8000]
        )
        
        logger.info(f"Parsing report {report_id}: {title[:50]}...")
        
        # Use instructor for structured output
        parsed = self.client.call_structured(
            prompt=prompt,
            response_model=LLMParsedReport,
            label="Parser"
        )
        
        if not parsed:
            logger.error(f"No response from LLM for report {report_id}")
            return None
        
        # Convert LLMParsedReport to ParsedReport
        result = ParsedReport(
            report_id=report_id,
            title=title,
            vuln_type=parsed.vuln_type,
            severity=severity,
            target_url=parsed.target_url,
            target_domain=parsed.target_domain,
            weakness=weakness_name,
            description=parsed.description,
            impact=parsed.impact,
            steps=parsed.steps,
            replay_method=parsed.replay_method,
            requires_auth=parsed.requires_auth,
            auth_details=parsed.auth_details,
            original_report_text=vuln_info,
            parsed_at=datetime.now(),
            confidence=parsed.confidence,
        )
        
        logger.info(
            f"Parsed report {report_id}: type={result.vuln_type}, "
            f"steps={len(result.steps)}, method={result.replay_method}, "
            f"confidence={result.confidence}"
        )
        
        return result
    
    def parse_batch(self, reports: list[dict], delay: float = 1.0) -> list[ParsedReport]:
        """Parse multiple reports with rate limiting."""
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
