"""
LLM-powered replay result validator — determines if a vulnerability still exists.

Uses instructor for guaranteed Pydantic structured output.
"""
from loguru import logger

from src.models import ReplayReport, ReplayResult, LLMValidationResult
from src.llm import LLMClient
from src.prompts import format_prompt


class LLMValidator:
    """Validates replay results using LLM with structured output."""
    
    def __init__(
        self,
        api_key: str,
        model: str = "llama-4-scout-17b-16e-instruct",
        confidence_threshold: float = 0.7,
        provider: str = "groq",
        verbose: bool = False,
    ):
        self.client = LLMClient(
            api_key=api_key,
            model=model,
            provider=provider,
            temperature=0.1,
            max_tokens=2048,
            verbose=verbose,
        )
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose
    
    def validate(self, replay_report: ReplayReport) -> ReplayReport:
        """
        Validate a replay report by analyzing the evidence with LLM.
        
        Uses instructor for guaranteed structured output.
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
        prompt = format_prompt(
            "validate_result",
            title=parsed.title,
            vuln_type=parsed.vuln_type,
            description=parsed.description,
            expected_behavior=expected_behavior,
            evidence_text=evidence_text[:8000]
        )
        
        logger.info(f"Validating replay for report {parsed.report_id}...")
        
        # Use instructor for structured output
        result = self.client.call_structured(
            prompt=prompt,
            response_model=LLMValidationResult,
            label="Validator"
        )
        
        if not result:
            replay_report.result = ReplayResult.INCONCLUSIVE
            replay_report.llm_analysis = "Validation failed: no LLM response"
            return replay_report
        
        # Update replay report with validated result
        replay_report.result = result.result
        replay_report.confidence = result.confidence
        
        analysis = result.analysis
        if result.indicators:
            analysis += "\n\nKey Indicators:\n" + "\n".join(f"  • {i}" for i in result.indicators)
        replay_report.llm_analysis = analysis
        
        logger.info(
            f"Validation result for {parsed.report_id}: "
            f"{replay_report.result} (confidence: {replay_report.confidence})"
        )
        
        return replay_report
