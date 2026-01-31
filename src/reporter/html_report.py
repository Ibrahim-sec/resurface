"""
HTML Report Generator for Resurface replay results
"""
import json
from pathlib import Path
from datetime import datetime
from loguru import logger


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resurface Report — {title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 2rem; }}
        
        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid #1a1a2e;
            margin-bottom: 2rem;
        }}
        header h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, #00d4ff, #7b2ff7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        header .subtitle {{ color: #888; margin-top: 0.5rem; }}
        
        .result-banner {{
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            font-size: 1.5rem;
            font-weight: bold;
            margin: 1.5rem 0;
        }}
        .result-vulnerable {{ background: #2d0000; border: 2px solid #ff4444; color: #ff4444; }}
        .result-fixed {{ background: #002d00; border: 2px solid #44ff44; color: #44ff44; }}
        .result-partial {{ background: #2d2d00; border: 2px solid #ffff44; color: #ffff44; }}
        .result-inconclusive {{ background: #1a1a2e; border: 2px solid #888; color: #888; }}
        .result-error {{ background: #2d0000; border: 2px solid #ff0000; color: #ff0000; }}
        
        .card {{
            background: #12121a;
            border: 1px solid #1a1a2e;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
        }}
        .card h2 {{
            color: #00d4ff;
            margin-bottom: 1rem;
            font-size: 1.2rem;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
        }}
        .meta-item {{ padding: 0.5rem; }}
        .meta-label {{ color: #888; font-size: 0.85rem; text-transform: uppercase; }}
        .meta-value {{ color: #fff; font-size: 1.1rem; margin-top: 0.25rem; }}
        
        .severity-critical {{ color: #ff0000; }}
        .severity-high {{ color: #ff4444; }}
        .severity-medium {{ color: #ffaa00; }}
        .severity-low {{ color: #44ff44; }}
        
        .step {{
            background: #0d0d14;
            border-left: 3px solid #7b2ff7;
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 0 8px 8px 0;
        }}
        .step-number {{
            display: inline-block;
            background: #7b2ff7;
            color: white;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            text-align: center;
            font-size: 0.8rem;
            line-height: 24px;
            margin-right: 0.5rem;
        }}
        
        pre {{
            background: #0a0a12;
            border: 1px solid #1a1a2e;
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            font-size: 0.85rem;
            color: #b0b0b0;
            margin: 0.5rem 0;
        }}
        
        .analysis {{ white-space: pre-wrap; color: #ccc; }}
        
        .confidence-bar {{
            background: #1a1a2e;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 0.5rem 0;
        }}
        .confidence-fill {{
            height: 100%;
            border-radius: 10px;
            transition: width 0.5s;
        }}
        
        footer {{
            text-align: center;
            padding: 2rem 0;
            color: #555;
            border-top: 1px solid #1a1a2e;
            margin-top: 2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔄 Resurface Report</h1>
            <p class="subtitle">Vulnerability Regression Analysis</p>
        </header>
        
        {result_banner}
        
        <div class="card">
            <h2>📋 Report Details</h2>
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Report ID</div>
                    <div class="meta-value">{report_id}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Title</div>
                    <div class="meta-value">{title}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Vulnerability Type</div>
                    <div class="meta-value">{vuln_type}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Severity</div>
                    <div class="meta-value severity-{severity}">{severity}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div class="meta-value">{target}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Tested At</div>
                    <div class="meta-value">{tested_at}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Duration</div>
                    <div class="meta-value">{duration}s</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Confidence</div>
                    <div class="meta-value">{confidence}%</div>
                </div>
            </div>
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: {confidence}%; background: {confidence_color};"></div>
            </div>
        </div>
        
        <div class="card">
            <h2>🧠 LLM Analysis</h2>
            <div class="analysis">{analysis}</div>
        </div>
        
        {steps_html}
        
        {evidence_html}
        
        <footer>
            <p>Generated by Resurface v0.1.0 — {generated_at}</p>
            <p><em>Bugs don't die. They resurface.</em></p>
        </footer>
    </div>
</body>
</html>"""


def generate_html_report(result_file: str, parsed_file: str = None, 
                         output_path: str = None) -> str:
    """Generate an HTML report from replay results"""
    
    with open(result_file) as f:
        result = json.load(f)
    
    report_id = result.get('report_id', '?')
    title = result.get('title', 'Unknown')
    vuln_type = result.get('vuln_type', 'unknown')
    severity = result.get('severity', 'unknown')
    target = result.get('target', '?')
    result_status = result.get('result', 'inconclusive')
    confidence = int(result.get('confidence', 0) * 100)
    analysis = result.get('analysis', 'No analysis available')
    duration = f"{result.get('duration_seconds', 0):.1f}"
    tested_at = result.get('replayed_at', 'Unknown')
    
    # Result banner
    banner_map = {
        'vulnerable': ('result-vulnerable', '🔴 VULNERABILITY HAS RESURFACED'),
        'fixed': ('result-fixed', '🟢 VULNERABILITY IS FIXED'),
        'partial': ('result-partial', '🟡 PARTIALLY FIXED — BYPASS MAY EXIST'),
        'inconclusive': ('result-inconclusive', '⚪ INCONCLUSIVE'),
        'error': ('result-error', '❌ REPLAY ERROR'),
    }
    banner_class, banner_text = banner_map.get(result_status, ('result-inconclusive', '?'))
    result_banner = f'<div class="result-banner {banner_class}">{banner_text}</div>'
    
    # Confidence color
    if confidence >= 80:
        confidence_color = '#44ff44'
    elif confidence >= 50:
        confidence_color = '#ffaa00'
    else:
        confidence_color = '#ff4444'
    
    # Steps HTML (from parsed file if available)
    steps_html = ""
    if parsed_file and Path(parsed_file).exists():
        with open(parsed_file) as f:
            parsed = json.load(f)
        
        steps = parsed.get('steps', [])
        if steps:
            steps_items = ""
            for step in steps:
                steps_items += f"""
                <div class="step">
                    <span class="step-number">{step.get('order', '?')}</span>
                    <strong>{step.get('description', 'No description')}</strong>
                    {'<br><code>' + step.get('method', '') + ' ' + (step.get('url') or '') + '</code>' if step.get('url') else ''}
                    {'<br>Payload: <code>' + step.get('payload', '') + '</code>' if step.get('payload') else ''}
                    {'<br>Expected: <em>' + step.get('expected_behavior', '') + '</em>' if step.get('expected_behavior') else ''}
                </div>"""
            
            steps_html = f"""
            <div class="card">
                <h2>📝 PoC Steps (LLM-Extracted)</h2>
                {steps_items}
            </div>"""
    
    # Evidence HTML
    evidence_html = ""
    evidence_count = result.get('evidence_count', 0)
    if evidence_count > 0:
        evidence_html = f"""
        <div class="card">
            <h2>📸 Evidence</h2>
            <p>{evidence_count} step(s) executed with request/response logs captured.</p>
            <p>Full evidence available in the JSON result file.</p>
        </div>"""
    
    html = HTML_TEMPLATE.format(
        title=title,
        report_id=report_id,
        vuln_type=vuln_type,
        severity=severity,
        target=target,
        tested_at=tested_at,
        duration=duration,
        confidence=confidence,
        confidence_color=confidence_color,
        result_banner=result_banner,
        analysis=analysis,
        steps_html=steps_html,
        evidence_html=evidence_html,
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    
    if not output_path:
        output_path = f"data/results/{report_id}_report.html"
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html)
    
    logger.info(f"HTML report saved to {output_path}")
    return output_path
