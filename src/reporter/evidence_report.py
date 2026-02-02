"""
Generate an HTML evidence report with annotated vision screenshots.
Shows step-by-step visual proof of what the LLM agent did during replay.
"""
import json
import base64
from pathlib import Path
from datetime import datetime


def generate_evidence_report(report_id: int, results_dir: str, reports_dir: str, output_path: str):
    """Generate HTML evidence report for a single replay."""
    results_dir = Path(results_dir)
    reports_dir = Path(reports_dir)
    
    # Load result
    result_path = results_dir / f"{report_id}_result.json"
    if not result_path.exists():
        raise FileNotFoundError(f"No result found for report {report_id}")
    
    with open(result_path) as f:
        result = json.load(f)
    
    # Load original report
    report_path = reports_dir / f"{report_id}.json"
    report_data = {}
    if report_path.exists():
        with open(report_path) as f:
            report_data = json.load(f)
    
    # Find screenshots
    screenshots = sorted(results_dir.glob(f"{report_id}_vision_step*.png"))
    final_ss = results_dir / f"{report_id}_vision_final.png"
    
    # Build HTML
    result_status = result.get('result', 'unknown').upper()
    result_emoji = {
        'VULNERABLE': '🔴', 'FIXED': '🟢', 'PARTIAL': '🟡',
        'INCONCLUSIVE': '⚪', 'ERROR': '❌',
    }.get(result_status, '?')
    
    result_color = {
        'VULNERABLE': '#dc3545', 'FIXED': '#28a745', 'PARTIAL': '#ffc107',
        'INCONCLUSIVE': '#6c757d', 'ERROR': '#dc3545',
    }.get(result_status, '#333')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Resurface Evidence — Report {report_id}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0d1117; color: #c9d1d9; padding: 2rem; }}
    .header {{ text-align: center; margin-bottom: 2rem; }}
    .header h1 {{ color: #58a6ff; font-size: 2rem; }}
    .header .subtitle {{ color: #8b949e; margin-top: 0.5rem; }}
    .result-badge {{ display: inline-block; padding: 0.5rem 1.5rem; border-radius: 8px;
                     font-size: 1.5rem; font-weight: bold; margin: 1rem 0;
                     background: {result_color}22; border: 2px solid {result_color};
                     color: {result_color}; }}
    .meta {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 1.5rem; margin-bottom: 2rem; }}
    .meta h2 {{ color: #58a6ff; margin-bottom: 1rem; font-size: 1.2rem; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                  gap: 1rem; }}
    .meta-item {{ }}
    .meta-item .label {{ color: #8b949e; font-size: 0.85rem; }}
    .meta-item .value {{ color: #c9d1d9; font-weight: 600; }}
    .step {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 1.5rem; margin-bottom: 1.5rem; }}
    .step h3 {{ color: #58a6ff; margin-bottom: 1rem; }}
    .step img {{ width: 100%; max-width: 1280px; border-radius: 4px;
                border: 1px solid #30363d; margin-top: 0.5rem; }}
    .step .action {{ background: #0d1117; border-radius: 4px; padding: 0.75rem;
                    margin-top: 0.5rem; font-family: monospace; font-size: 0.9rem;
                    color: #7ee787; }}
    .analysis {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                padding: 1.5rem; margin-bottom: 1.5rem; }}
    .analysis h2 {{ color: #58a6ff; margin-bottom: 1rem; }}
    .analysis p {{ line-height: 1.6; }}
    .footer {{ text-align: center; color: #484f58; margin-top: 2rem; padding-top: 1rem;
              border-top: 1px solid #21262d; }}
</style>
</head>
<body>
<div class="header">
    <h1>🔄 Resurface — Evidence Report</h1>
    <div class="subtitle">LLM-Powered Vulnerability Regression Hunter</div>
    <div class="result-badge">{result_emoji} {result_status}</div>
</div>

<div class="meta">
    <h2>Report Details</h2>
    <div class="meta-grid">
        <div class="meta-item">
            <div class="label">Report ID</div>
            <div class="value">{report_id}</div>
        </div>
        <div class="meta-item">
            <div class="label">Title</div>
            <div class="value">{result.get('title', report_data.get('title', 'N/A'))}</div>
        </div>
        <div class="meta-item">
            <div class="label">Vulnerability Type</div>
            <div class="value">{result.get('vuln_type', 'N/A')}</div>
        </div>
        <div class="meta-item">
            <div class="label">Target</div>
            <div class="value">{result.get('target', 'N/A')}</div>
        </div>
        <div class="meta-item">
            <div class="label">Confidence</div>
            <div class="value">{int(result.get('confidence', 0) * 100)}%</div>
        </div>
        <div class="meta-item">
            <div class="label">Duration</div>
            <div class="value">{result.get('duration_seconds', 0):.1f}s</div>
        </div>
        <div class="meta-item">
            <div class="label">Steps Executed</div>
            <div class="value">{result.get('evidence_count', len(screenshots))}</div>
        </div>
        <div class="meta-item">
            <div class="label">Replayed At</div>
            <div class="value">{result.get('replayed_at', 'N/A')[:19]}</div>
        </div>
    </div>
</div>
"""

    # Add vulnerability description
    vuln_info = report_data.get('vulnerability_information', '')
    if vuln_info:
        # Escape HTML
        vuln_info_escaped = vuln_info.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
        html += f"""
<div class="analysis">
    <h2>Vulnerability Report</h2>
    <p style="font-size: 0.9rem;">{vuln_info_escaped}</p>
</div>
"""

    # Add screenshots
    if screenshots:
        html += '<h2 style="color: #58a6ff; margin-bottom: 1rem;">📸 Step-by-Step Evidence</h2>\n'
        for i, ss_path in enumerate(screenshots, 1):
            # Embed image as base64
            with open(ss_path, 'rb') as img_f:
                img_b64 = base64.b64encode(img_f.read()).decode()
            
            html += f"""
<div class="step">
    <h3>Step {i}</h3>
    <img src="data:image/png;base64,{img_b64}" alt="Step {i} screenshot">
</div>
"""

    # Add final screenshot
    if final_ss.exists():
        with open(final_ss, 'rb') as img_f:
            final_b64 = base64.b64encode(img_f.read()).decode()
        html += f"""
<div class="step">
    <h3>📸 Final State</h3>
    <img src="data:image/png;base64,{final_b64}" alt="Final state screenshot">
</div>
"""

    # Add analysis
    analysis = result.get('analysis', '')
    if analysis:
        html += f"""
<div class="analysis">
    <h2>LLM Analysis</h2>
    <p>{analysis}</p>
</div>
"""

    html += f"""
<div class="footer">
    Generated by Resurface v1.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
</body>
</html>"""

    # Write
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, 'w') as f:
        f.write(html)
    
    return output


def generate_multi_evidence_report(report_ids: list, results_dir: str, reports_dir: str, output_path: str):
    """Generate a combined evidence report for multiple replays."""
    # For now, generate individual reports
    outputs = []
    for rid in report_ids:
        try:
            out = generate_evidence_report(
                rid, results_dir, reports_dir,
                str(Path(output_path).parent / f"evidence_{rid}.html")
            )
            outputs.append(out)
        except FileNotFoundError:
            continue
    return outputs
