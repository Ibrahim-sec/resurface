#!/usr/bin/env python3
"""
Convert HackerOne reports to training data format.
Extracts vulnerability info and structures it for fine-tuning.
"""
import json
import re
from pathlib import Path
from typing import Optional

REPORTS_DIR = Path(__file__).parent.parent / "data" / "reports"
OUTPUT_FILE = Path(__file__).parent / "data" / "train_hackerone.jsonl"

# Weakness ID to category mapping
WEAKNESS_MAP = {
    "xss": "xss_reflected",
    "cross-site scripting": "xss_reflected",
    "stored xss": "xss_stored",
    "sql injection": "sqli",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "idor": "broken_access_control",
    "insecure direct object": "broken_access_control",
    "broken access control": "broken_access_control",
    "authentication": "auth_bypass",
    "authorization": "broken_access_control",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "rce",
    "os command injection": "rce",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "lfi": "path_traversal",
    "file inclusion": "path_traversal",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "open redirect": "open_redirect",
    "information disclosure": "info_disclosure",
    "sensitive data exposure": "info_disclosure",
    "deserialization": "deserialization",
    "prototype pollution": "prototype_pollution",
    "race condition": "race_condition",
    "clickjacking": "clickjacking",
    "cors": "cors",
    "jwt": "jwt",
    "ssti": "ssti",
    "template injection": "ssti",
    "file upload": "file_upload",
    "unrestricted file upload": "file_upload",
}

def get_category(report: dict) -> str:
    """Extract vulnerability category from report."""
    weakness = report.get("weakness", {})
    if isinstance(weakness, dict):
        weakness_name = weakness.get("name", "").lower()
    else:
        weakness_name = ""
    
    # Try to match weakness name
    for key, cat in WEAKNESS_MAP.items():
        if key in weakness_name:
            return cat
    
    # Try title
    title = report.get("title", "").lower()
    for key, cat in WEAKNESS_MAP.items():
        if key in title:
            return cat
    
    return "unknown"

def extract_steps(vuln_info: str) -> str:
    """Extract exploitation steps from vulnerability information."""
    # Look for numbered lists or step patterns
    lines = vuln_info.split('\n')
    steps = []
    in_steps = False
    
    for line in lines:
        line = line.strip()
        # Check for step patterns
        if re.match(r'^(\d+[\.\)]\s*|step\s*\d+|[-*]\s*)', line, re.I):
            in_steps = True
            steps.append(line)
        elif in_steps and line and not line.startswith('#'):
            steps.append(line)
        elif in_steps and not line:
            if len(steps) > 2:
                break
    
    if steps:
        return '\n'.join(steps[:15])  # Limit to 15 steps
    
    # Fallback: just use first few paragraphs
    paragraphs = [p.strip() for p in vuln_info.split('\n\n') if p.strip()]
    return '\n\n'.join(paragraphs[:3])

def extract_payloads(vuln_info: str) -> str:
    """Extract payloads from vulnerability information."""
    payloads = []
    
    # Look for code blocks
    code_blocks = re.findall(r'```[\s\S]*?```|`[^`]+`', vuln_info)
    for block in code_blocks[:10]:
        clean = block.strip('`').strip()
        if clean and len(clean) < 500:
            payloads.append(f"- `{clean[:100]}`")
    
    # Look for URL patterns
    urls = re.findall(r'https?://[^\s<>"]+', vuln_info)
    for url in urls[:5]:
        payloads.append(f"- `{url}`")
    
    if payloads:
        return '\n'.join(payloads[:10])
    return "- See steps above for specific payloads"

def get_indicators(category: str) -> str:
    """Get success indicators based on category."""
    indicators = {
        "xss_reflected": "- Alert/popup displayed\n- JavaScript executed in browser\n- Cookie/session data accessible",
        "xss_stored": "- Payload persists across page loads\n- Other users affected\n- JavaScript executes on view",
        "sqli": "- Database data retrieved\n- Error messages reveal DB info\n- UNION query successful",
        "ssrf": "- Internal service accessed\n- Metadata endpoint reached\n- Internal IP/port scanned",
        "broken_access_control": "- Unauthorized data accessed\n- Other user's resources visible\n- Admin functions available",
        "auth_bypass": "- Logged in without valid credentials\n- Session hijacked\n- 2FA bypassed",
        "rce": "- Command output visible\n- File created on server\n- Reverse shell connected",
        "path_traversal": "- /etc/passwd contents visible\n- Arbitrary file read successful\n- Directory listing obtained",
    }
    return indicators.get(category, "- Vulnerability successfully exploited\n- Unauthorized access achieved\n- Application behavior confirms issue")

def convert_report(report: dict) -> Optional[dict]:
    """Convert a single HackerOne report to training format."""
    vuln_info = report.get("vulnerability_information", "")
    if not vuln_info or len(vuln_info) < 100:
        return None
    
    title = report.get("title", "Unknown Vulnerability")
    category = get_category(report)
    severity = report.get("severity_rating", "unknown")
    
    # Build the training example
    steps = extract_steps(vuln_info)
    payloads = extract_payloads(vuln_info)
    indicators = get_indicators(category)
    
    # Skip if we couldn't extract meaningful steps
    if len(steps) < 50:
        return None
    
    user_content = f"""You are a security researcher testing a web application for vulnerabilities.

**Vulnerability Type:** {category}
**Scenario:** {title}

Generate a step-by-step exploitation methodology for this vulnerability. Include:
1. Detailed exploitation steps
2. Key payloads to use
3. Indicators that confirm successful exploitation"""

    assistant_content = f"""## Exploitation Methodology: {title}

### Step-by-Step Exploitation
{steps}

### Key Payloads
{payloads}

### Success Indicators
{indicators}"""

    return {
        "messages": [
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content}
        ]
    }

def main():
    if not REPORTS_DIR.exists():
        print(f"Reports directory not found: {REPORTS_DIR}")
        return
    
    converted = []
    skipped = 0
    
    for report_file in sorted(REPORTS_DIR.glob("*.json")):
        try:
            with open(report_file) as f:
                report = json.load(f)
            
            # Skip test reports (9xxxxx IDs)
            report_id = report.get("id", 0)
            if isinstance(report_id, int) and report_id >= 900000:
                continue
            
            example = convert_report(report)
            if example:
                converted.append(example)
                print(f"✅ {report_file.name}: {report.get('title', 'Unknown')[:50]}")
            else:
                skipped += 1
        except Exception as e:
            print(f"❌ {report_file.name}: {e}")
            skipped += 1
    
    print(f"\nConverted: {len(converted)} | Skipped: {skipped}")
    
    if converted:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, 'w') as f:
            for ex in converted:
                f.write(json.dumps(ex) + '\n')
        print(f"Saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
