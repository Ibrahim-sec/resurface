#!/usr/bin/env python3
"""
Security Report Generator
Generates professional security assessment reports from replay results.
"""
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
import json

from src.models import ReplayReport, ReplayResult, ParsedReport


class ReportGenerator:
    """Generate security assessment reports from replay results."""
    
    TEMPLATE_PATH = Path(__file__).parent / "templates" / "security_report.md"
    
    # Proof level descriptions
    PROOF_LEVELS = {
        1: "Payload blocked/encoded - NOT VULNERABLE",
        2: "Payload injected but execution blocked - PARTIAL (WAF/CSP)",
        3: "Vulnerability behavior confirmed - VULNERABLE",
        4: "Critical impact demonstrated - VULNERABLE (CRITICAL)",
    }
    
    # Result to verdict mapping
    VERDICT_MAP = {
        ReplayResult.VULNERABLE: "VULNERABLE",
        ReplayResult.FIXED: "FIXED",
        ReplayResult.INCONCLUSIVE: "INCONCLUSIVE",
        ReplayResult.ERROR: "ERROR",
    }
    
    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._load_template()
    
    def _load_template(self):
        """Load the report template."""
        if self.TEMPLATE_PATH.exists():
            self.template = self.TEMPLATE_PATH.read_text()
        else:
            # Fallback minimal template
            self.template = "# Report\n\n{content}"
    
    def _determine_proof_level(self, replay: ReplayReport) -> int:
        """Determine the proof level achieved based on replay results."""
        if replay.result == ReplayResult.VULNERABLE:
            if replay.confidence >= 0.9:
                return 4  # Critical impact
            return 3  # Confirmed
        elif replay.result == ReplayResult.FIXED:
            return 1  # Blocked/encoded
        else:
            return 2  # Partial/inconclusive
    
    def _format_steps(self, parsed_report: ParsedReport) -> str:
        """Format the PoC steps as markdown."""
        if not parsed_report.steps:
            return "No specific steps documented."
        
        lines = []
        for step in parsed_report.steps:
            lines.append(f"{step.order}. {step.description}")
            if step.url:
                lines.append(f"   - URL: `{step.url}`")
            if step.payload:
                lines.append(f"   - Payload: `{step.payload}`")
            if step.expected_behavior:
                lines.append(f"   - Expected: {step.expected_behavior}")
        return "\n".join(lines)
    
    def _format_evidence(self, replay: ReplayReport) -> str:
        """Format evidence from replay results."""
        if not replay.llm_analysis:
            return "No detailed evidence captured."
        return replay.llm_analysis[:2000]  # Truncate if too long
    
    def _get_recommendations(self, parsed_report: ParsedReport, replay: ReplayReport) -> str:
        """Generate recommendations based on results."""
        if replay.result == ReplayResult.VULNERABLE:
            return (
                f"**URGENT:** The {parsed_report.vuln_type.value} vulnerability is still exploitable.\n\n"
                "Recommended actions:\n"
                "1. Immediately patch the vulnerable endpoint\n"
                "2. Implement input validation and output encoding\n"
                "3. Add security controls (WAF rules, CSP headers)\n"
                "4. Re-test after remediation"
            )
        elif replay.result == ReplayResult.FIXED:
            return (
                "The vulnerability appears to be fixed.\n\n"
                "Recommended actions:\n"
                "1. Verify fix covers all attack vectors\n"
                "2. Add regression tests to CI/CD\n"
                "3. Monitor for bypass attempts"
            )
        else:
            return (
                "Could not conclusively determine vulnerability status.\n\n"
                "Recommended actions:\n"
                "1. Manual verification required\n"
                "2. Check if endpoint or auth has changed\n"
                "3. Review with security team"
            )
    
    def generate(
        self,
        parsed_report: ParsedReport,
        replay: ReplayReport,
        target_url: str,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a complete security report."""
        
        proof_level = self._determine_proof_level(replay)
        
        # Build level status indicators
        level_statuses = {}
        for i in range(1, 5):
            if i < proof_level:
                level_statuses[f"level{i}_status"] = "✅ Passed"
            elif i == proof_level:
                level_statuses[f"level{i}_status"] = "⚠️ **Current Level**"
            else:
                level_statuses[f"level{i}_status"] = "—"
        
        # Format screenshots
        screenshots = "No screenshots captured."
        if hasattr(replay, 'screenshots') and replay.screenshots:
            screenshots = "\n".join([f"![Evidence]({s})" for s in replay.screenshots])
        
        # Build the report
        report = self.template.format(
            target_url=target_url,
            date=datetime.now().strftime("%Y-%m-%d"),
            report_id=parsed_report.report_id,
            vuln_title=parsed_report.title,
            vuln_type=parsed_report.vuln_type.value if parsed_report.vuln_type else "unknown",
            status=self.VERDICT_MAP.get(replay.result, "UNKNOWN"),
            confidence=int(replay.confidence * 100),
            summary=replay.llm_analysis[:500] if replay.llm_analysis else "No summary available.",
            severity=parsed_report.severity or "Unknown",
            description=parsed_report.description or "No description provided.",
            expected_behavior=parsed_report.steps[0].expected_behavior if parsed_report.steps else "N/A",
            proof_level=self.PROOF_LEVELS.get(proof_level, "Unknown"),
            steps_executed=self._format_steps(parsed_report),
            payloads_used="\n".join([s.payload for s in parsed_report.steps if s.payload]) or "N/A",
            response_evidence=self._format_evidence(replay),
            screenshots=screenshots,
            verdict=self.VERDICT_MAP.get(replay.result, "UNKNOWN"),
            recommendations=self._get_recommendations(parsed_report, replay),
            request_response_log="See evidence chain for full details.",
            evidence_timeline="See evidence directory for timeline.",
            generated_at=datetime.now().isoformat(),
            **level_statuses,
        )
        
        return report
    
    def save(
        self,
        parsed_report: ParsedReport,
        replay: ReplayReport,
        target_url: str,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate and save the report to a file."""
        report_content = self.generate(parsed_report, replay, target_url)
        
        if filename is None:
            filename = f"report_{parsed_report.report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        output_path = self.output_dir / filename
        output_path.write_text(report_content)
        
        return output_path


# CLI usage
if __name__ == "__main__":
    print("Report generator module. Import and use ReportGenerator class.")
