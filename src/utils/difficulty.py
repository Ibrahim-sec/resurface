"""
Auto-classify report difficulty based on content analysis.

Easy: Has exact URLs, payloads, step-by-step instructions
Medium: Has some hints but missing key details
Hard: Only vulnerability type and vague description
"""
import json
from pathlib import Path


def score_report_difficulty(report_path: str, parsed_path: str = None) -> dict:
    """
    Score a report's difficulty for automated replay.
    
    If the report JSON contains an explicit "difficulty" field, that value is
    used directly (score is set to a synthetic value for ordering).
    Otherwise, auto-scores based on content analysis.
    
    Returns:
        {
            'difficulty': 'easy' | 'medium' | 'hard',
            'score': 0-100 (higher = easier to replay),
            'factors': { ... }
        }
    """
    report = {}
    parsed = {}
    
    if Path(report_path).exists():
        with open(report_path) as f:
            report = json.load(f)
    
    if parsed_path and Path(parsed_path).exists():
        with open(parsed_path) as f:
            parsed = json.load(f)
    
    # Respect explicit difficulty override in report JSON
    explicit = report.get('difficulty')
    if explicit and explicit in ('easy', 'medium', 'hard'):
        synthetic_score = {'easy': 80, 'medium': 45, 'hard': 15}[explicit]
        return {
            'difficulty': explicit,
            'score': synthetic_score,
            'factors': {'explicit_override': True},
        }
    
    vuln_info = report.get('vulnerability_information', '')
    steps = parsed.get('steps', [])
    
    factors = {
        'has_url': False,
        'has_payload': False,
        'has_steps': len(steps) > 0,
        'step_count': len(steps),
        'has_exact_endpoint': False,
        'has_http_method': False,
        'has_request_body': False,
        'has_expected_behavior': False,
        'description_length': len(vuln_info),
    }
    
    # Check vuln_info for indicators
    vuln_lower = vuln_info.lower()
    
    # URL detection
    if 'http://' in vuln_info or 'https://' in vuln_info:
        factors['has_url'] = True
    if any(ep in vuln_lower for ep in ['/#/', '/api/', '/rest/', '/vulnerabilities/', '/admin']):
        factors['has_exact_endpoint'] = True
    
    # Payload detection
    payload_indicators = [
        '<script', '<iframe', '<img', 'alert(', 'onerror=',  # XSS
        "' or ", "' and ", '1=1', 'union select', '--',  # SQLi
        '../', '..%2f', '%00',  # Path traversal
        '"role"', '"admin"',  # Priv esc
    ]
    if any(ind in vuln_lower for ind in payload_indicators):
        factors['has_payload'] = True
    
    # Step-level analysis
    for step in steps:
        url = step.get('url') or ''
        if url and ('http' in url or '/' in url):
            factors['has_url'] = True
            if any(ep in url.lower() for ep in ['/api/', '/rest/', '/#/', '/login', '/vulnerabilities/']):
                factors['has_exact_endpoint'] = True
        
        method = step.get('method') or ''
        if method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH'):
            factors['has_http_method'] = True
        
        body = step.get('body') or ''
        if body and len(body) > 5:
            factors['has_request_body'] = True
        
        payload = step.get('payload') or ''
        if payload and len(payload) > 3:
            factors['has_payload'] = True
        
        expected = step.get('expected_behavior') or ''
        if expected and len(expected) > 10:
            factors['has_expected_behavior'] = True
    
    # Calculate score (0-100, higher = easier)
    score = 0
    score += 25 if factors['has_url'] else 0
    score += 20 if factors['has_payload'] else 0
    score += 15 if factors['has_exact_endpoint'] else 0
    score += 10 if factors['has_http_method'] else 0
    score += 10 if factors['has_request_body'] else 0
    score += 10 if factors['has_expected_behavior'] else 0
    score += 5 if factors['step_count'] >= 3 else 0
    score += 5 if factors['description_length'] > 500 else 0
    
    # Classify
    if score >= 60:
        difficulty = 'easy'
    elif score >= 30:
        difficulty = 'medium'
    else:
        difficulty = 'hard'
    
    return {
        'difficulty': difficulty,
        'score': score,
        'factors': factors,
    }


def score_all_reports(data_dir: str) -> list:
    """Score all reports in the data directory."""
    data = Path(data_dir)
    reports_dir = data / 'reports'
    parsed_dir = data / 'parsed'
    
    results = []
    for report_file in sorted(reports_dir.glob('*.json')):
        rid = report_file.stem
        parsed_file = parsed_dir / f"{rid}_parsed.json"
        
        score_data = score_report_difficulty(
            str(report_file),
            str(parsed_file) if parsed_file.exists() else None
        )
        score_data['report_id'] = rid
        
        # Get title
        try:
            with open(report_file) as f:
                score_data['title'] = json.load(f).get('title', '')[:50]
        except Exception:
            score_data['title'] = ''
        
        results.append(score_data)
    
    return results
