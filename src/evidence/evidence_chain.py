"""
Evidence Chain — structured evidence collection for vulnerability replay verification.

Captures every step of a replay as a chain of linked evidence items.
Each link records: what was done, what happened, and proof.
"""

from __future__ import annotations

import base64
import html as html_mod
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class EvidenceLink:
    """A single piece of evidence in the replay chain."""

    step_number: int
    timestamp: float  # time.time()
    action_type: str  # "navigate", "click", "type", "api_request", "screenshot", "dom_capture", "finding"
    description: str  # Human-readable description of what happened

    # Request/response (for API calls)
    request_method: Optional[str] = None
    request_url: Optional[str] = None
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_body: Optional[str] = None  # Truncated to 2000 chars

    # Visual evidence
    screenshot_path: Optional[str] = None
    screenshot_base64: Optional[str] = None  # For embedded HTML reports

    # DOM evidence
    dom_snapshot_path: Optional[str] = None
    dom_snippet: Optional[str] = None  # Relevant HTML excerpt

    # Verdict/analysis
    verdict: Optional[str] = None  # "VULNERABLE", "BLOCKED", "NEEDS_MORE", "CLEAN"
    confidence: float = 0.0
    notes: str = ""


class EvidenceChain:
    """Collects and manages a chain of evidence links for a single replay."""

    _MAX_RESPONSE_BODY = 2000

    def __init__(
        self,
        report_id: int,
        target_url: str,
        vuln_type: str,
        evidence_dir: str = "data/results",
    ):
        self.report_id = report_id
        self.target_url = target_url
        self.vuln_type = vuln_type
        self.evidence_dir = Path(evidence_dir)
        self.links: list[EvidenceLink] = []
        self.start_time = time.time()
        self.final_verdict: Optional[str] = None
        self.final_confidence: float = 0.0

    # ------------------------------------------------------------------
    # Core helpers
    # ------------------------------------------------------------------

    def _next_step(self) -> int:
        return len(self.links) + 1

    def _ensure_dir(self) -> Path:
        chain_dir = self.evidence_dir / str(self.report_id)
        chain_dir.mkdir(parents=True, exist_ok=True)
        return chain_dir

    # ------------------------------------------------------------------
    # Adding evidence
    # ------------------------------------------------------------------

    def add_link(self, action_type: str, description: str, **kwargs) -> EvidenceLink:
        """Add a new evidence link to the chain. Returns the created link."""
        link = EvidenceLink(
            step_number=self._next_step(),
            timestamp=time.time(),
            action_type=action_type,
            description=description,
            **kwargs,
        )
        self.links.append(link)
        return link

    def add_request(
        self,
        method: str,
        url: str,
        body: Optional[str],
        status: int,
        response: str,
        **kwargs,
    ) -> EvidenceLink:
        """Convenience: add an API request evidence link."""
        truncated = response[: self._MAX_RESPONSE_BODY] if response else response
        description = kwargs.pop("description", f"{method} {url} → {status}")
        return self.add_link(
            action_type="api_request",
            description=description,
            request_method=method,
            request_url=url,
            request_body=body,
            response_status=status,
            response_body=truncated,
            **kwargs,
        )

    def add_screenshot(
        self, screenshot_bytes: bytes, description: str = ""
    ) -> EvidenceLink:
        """Save screenshot to file and add as evidence link. Returns link with path set."""
        chain_dir = self._ensure_dir()
        step = self._next_step()
        filename = f"step_{step:03d}_screenshot.png"
        filepath = chain_dir / filename

        filepath.write_bytes(screenshot_bytes)

        b64 = base64.b64encode(screenshot_bytes).decode("ascii")

        return self.add_link(
            action_type="screenshot",
            description=description or f"Screenshot captured (step {step})",
            screenshot_path=str(filepath),
            screenshot_base64=b64,
        )

    def add_dom(self, html: str, description: str = "") -> EvidenceLink:
        """Save DOM snapshot to file and add as evidence link."""
        chain_dir = self._ensure_dir()
        step = self._next_step()
        filename = f"step_{step:03d}_dom.html"
        filepath = chain_dir / filename

        filepath.write_text(html, encoding="utf-8")

        # Keep first 500 chars as snippet for quick reference
        snippet = html[:500]

        return self.add_link(
            action_type="dom_capture",
            description=description or f"DOM snapshot captured (step {step})",
            dom_snapshot_path=str(filepath),
            dom_snippet=snippet,
        )

    def add_finding(
        self, verdict: str, confidence: float, evidence_text: str
    ) -> EvidenceLink:
        """Add a finding/verdict link."""
        return self.add_link(
            action_type="finding",
            description=evidence_text,
            verdict=verdict,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------

    def set_final_verdict(self, verdict: str, confidence: float) -> None:
        """Set the overall chain verdict."""
        self.final_verdict = verdict
        self.final_confidence = confidence

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def duration(self) -> float:
        """Seconds since chain started."""
        return time.time() - self.start_time

    @property
    def summary(self) -> str:
        """One-line summary, e.g. '5 steps, 2 requests, 1 finding, verdict: VULNERABLE (95%)'"""
        total = len(self.links)
        requests = sum(1 for l in self.links if l.action_type == "api_request")
        findings = sum(1 for l in self.links if l.action_type == "finding")
        verdict_str = self.final_verdict or "PENDING"
        conf_pct = int(self.final_confidence * 100)
        return (
            f"{total} steps, {requests} requests, {findings} finding{'s' if findings != 1 else ''}, "
            f"verdict: {verdict_str} ({conf_pct}%)"
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Export chain as serializable dict."""
        return {
            "report_id": self.report_id,
            "target_url": self.target_url,
            "vuln_type": self.vuln_type,
            "start_time": self.start_time,
            "duration": self.duration,
            "final_verdict": self.final_verdict,
            "final_confidence": self.final_confidence,
            "summary": self.summary,
            "links": [asdict(link) for link in self.links],
        }

    def save_json(self, path: Optional[str] = None) -> str:
        """Save chain to JSON file. Default: evidence_dir/report_id_chain.json"""
        if path is None:
            self._ensure_dir()
            dest = self.evidence_dir / str(self.report_id) / f"{self.report_id}_chain.json"
        else:
            dest = Path(path)
            dest.parent.mkdir(parents=True, exist_ok=True)

        dest.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return str(dest)

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def to_html(self) -> str:  # noqa: C901 — template method, long by nature
        """Generate a self-contained HTML evidence report."""

        esc = html_mod.escape

        verdict_colors = {
            "VULNERABLE": "#ff4444",
            "CLEAN": "#44ff44",
            "NEEDS_MORE": "#ffdd44",
            "BLOCKED": "#ff8844",
        }
        badge_color = verdict_colors.get(self.final_verdict or "", "#888888")
        duration_s = self.duration
        duration_fmt = f"{duration_s:.1f}s" if duration_s < 60 else f"{duration_s / 60:.1f}m"
        conf_pct = int(self.final_confidence * 100)
        gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # --- Build step rows ---
        steps_html_parts: list[str] = []
        for link in self.links:
            ts = datetime.fromtimestamp(link.timestamp, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]

            # Action type badge colours
            type_colors = {
                "navigate": "#5b9bd5",
                "click": "#a3d977",
                "type": "#d9a3d5",
                "api_request": "#d5a85b",
                "screenshot": "#5bd5c5",
                "dom_capture": "#8888cc",
                "finding": verdict_colors.get(link.verdict or "", "#cccccc"),
            }
            type_bg = type_colors.get(link.action_type, "#666666")

            # Start step container
            step = []
            step.append(
                f'<div class="step">'
                f'  <div class="step-num">{link.step_number}</div>'
                f'  <div class="step-body">'
                f'    <div class="step-header">'
                f'      <span class="ts">{esc(ts)}</span>'
                f'      <span class="badge" style="background:{type_bg}">{esc(link.action_type)}</span>'
                f'      <span class="desc">{esc(link.description)}</span>'
                f'    </div>'
            )

            # API request details
            if link.action_type == "api_request" and link.request_url:
                status_color = "#44ff44" if link.response_status and link.response_status < 400 else "#ff4444"
                step.append(
                    f'<div class="code-block">'
                    f'<span style="color:#5b9bd5">{esc(link.request_method or "GET")}</span> '
                    f'{esc(link.request_url)} → '
                    f'<span style="color:{status_color}">{link.response_status}</span>'
                    f'</div>'
                )
                # Collapsible request body
                if link.request_body:
                    step.append(
                        f'<details class="collapsible">'
                        f'<summary>Request Body</summary>'
                        f'<pre>{esc(link.request_body)}</pre>'
                        f'</details>'
                    )
                # Collapsible response body
                if link.response_body:
                    step.append(
                        f'<details class="collapsible">'
                        f'<summary>Response Body</summary>'
                        f'<pre>{esc(link.response_body)}</pre>'
                        f'</details>'
                    )

            # Screenshot
            if link.screenshot_base64:
                step.append(
                    f'<div class="screenshot">'
                    f'<img src="data:image/png;base64,{link.screenshot_base64}" '
                    f'alt="Step {link.step_number} screenshot" />'
                    f'</div>'
                )

            # DOM snippet
            if link.dom_snippet:
                step.append(
                    f'<details class="collapsible">'
                    f'<summary>DOM Snippet</summary>'
                    f'<pre>{esc(link.dom_snippet)}</pre>'
                    f'</details>'
                )

            # Finding verdict badge
            if link.action_type == "finding" and link.verdict:
                v_color = verdict_colors.get(link.verdict, "#888888")
                link_conf = int(link.confidence * 100)
                step.append(
                    f'<div class="finding">'
                    f'<span class="verdict-badge" style="background:{v_color}">'
                    f'{esc(link.verdict)} ({link_conf}%)</span>'
                    f'</div>'
                )

            # Notes
            if link.notes:
                step.append(f'<div class="notes">{esc(link.notes)}</div>')

            step.append('  </div>')  # close step-body
            step.append('</div>')    # close step
            steps_html_parts.append("\n".join(step))

        steps_html = "\n".join(steps_html_parts)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Evidence Report — #{self.report_id}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    line-height: 1.6;
    padding: 0;
  }}
  /* Summary bar */
  .summary {{
    background: #16213e;
    padding: 24px 32px;
    border-bottom: 2px solid #0f3460;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 24px;
  }}
  .summary h1 {{
    font-size: 1.4em;
    color: #e94560;
    margin-right: auto;
  }}
  .summary .meta {{
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    font-size: 0.9em;
  }}
  .summary .meta span {{
    background: #1a1a2e;
    padding: 4px 12px;
    border-radius: 6px;
    border: 1px solid #333;
  }}
  .summary .meta .label {{
    color: #888;
    font-size: 0.8em;
    display: block;
  }}
  .verdict-big {{
    display: inline-block;
    padding: 8px 20px;
    border-radius: 8px;
    font-weight: bold;
    font-size: 1.2em;
    color: #1a1a2e;
  }}
  /* Timeline */
  .timeline {{
    padding: 32px;
    max-width: 1100px;
    margin: 0 auto;
  }}
  .step {{
    display: flex;
    gap: 16px;
    margin-bottom: 20px;
    position: relative;
  }}
  .step::before {{
    content: '';
    position: absolute;
    left: 22px;
    top: 40px;
    bottom: -20px;
    width: 2px;
    background: #333;
  }}
  .step:last-child::before {{ display: none; }}
  .step-num {{
    width: 44px;
    height: 44px;
    border-radius: 50%;
    background: #0f3460;
    color: #e0e0e0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    font-size: 0.95em;
    flex-shrink: 0;
    z-index: 1;
  }}
  .step-body {{
    flex: 1;
    background: #16213e;
    border-radius: 8px;
    padding: 16px 20px;
    border: 1px solid #0f3460;
  }}
  .step-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }}
  .ts {{
    font-size: 0.8em;
    color: #888;
    font-family: monospace;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 0.8em;
    font-weight: 600;
    color: #1a1a2e;
    text-transform: uppercase;
  }}
  .desc {{
    flex: 1;
  }}
  .code-block {{
    background: #0d1117;
    padding: 10px 14px;
    border-radius: 6px;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 0.9em;
    margin: 8px 0;
    overflow-x: auto;
  }}
  .collapsible {{
    margin: 8px 0;
  }}
  .collapsible summary {{
    cursor: pointer;
    color: #5b9bd5;
    font-size: 0.85em;
    padding: 4px 0;
  }}
  .collapsible summary:hover {{ color: #7bb8e8; }}
  .collapsible pre {{
    background: #0d1117;
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 0.85em;
    overflow-x: auto;
    max-height: 300px;
    overflow-y: auto;
    margin-top: 4px;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .screenshot img {{
    max-width: 100%;
    border-radius: 6px;
    border: 1px solid #333;
    margin: 8px 0;
  }}
  .finding {{
    margin: 8px 0;
  }}
  .verdict-badge {{
    display: inline-block;
    padding: 4px 14px;
    border-radius: 6px;
    font-weight: bold;
    color: #1a1a2e;
    font-size: 0.95em;
  }}
  .notes {{
    font-size: 0.85em;
    color: #aaa;
    font-style: italic;
    margin-top: 6px;
  }}
  /* Footer */
  .footer {{
    text-align: center;
    padding: 24px;
    font-size: 0.8em;
    color: #555;
    border-top: 1px solid #222;
    margin-top: 32px;
  }}
</style>
</head>
<body>
  <div class="summary">
    <h1>Evidence Report</h1>
    <div class="meta">
      <span><span class="label">Report ID</span>#{self.report_id}</span>
      <span><span class="label">Target</span>{esc(self.target_url)}</span>
      <span><span class="label">Vuln Type</span>{esc(self.vuln_type)}</span>
      <span><span class="label">Duration</span>{duration_fmt}</span>
    </div>
    <span class="verdict-big" style="background:{badge_color}">
      {esc(self.final_verdict or 'PENDING')} ({conf_pct}%)
    </span>
  </div>
  <div class="timeline">
    {steps_html}
  </div>
  <div class="footer">
    Generated {gen_time} &middot; Resurface Evidence Chain
  </div>
</body>
</html>"""

    def save_html(self, path: Optional[str] = None) -> str:
        """Save HTML report. Default: evidence_dir/report_id_evidence.html"""
        if path is None:
            self._ensure_dir()
            dest = self.evidence_dir / str(self.report_id) / f"{self.report_id}_evidence.html"
        else:
            dest = Path(path)
            dest.parent.mkdir(parents=True, exist_ok=True)

        dest.write_text(self.to_html(), encoding="utf-8")
        return str(dest)
