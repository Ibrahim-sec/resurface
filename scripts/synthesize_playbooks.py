#!/usr/bin/env python3
"""
Synthesize comprehensive playbooks from PortSwigger lab data.
Extracts techniques and patterns, removes lab-specific artifacts.
"""

import json
import re
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path(__file__).parent.parent / "data" / "portswigger_labs"
OUTPUT_DIR = Path(__file__).parent.parent / "src" / "prompts" / "playbooks"

# PortSwigger-specific patterns to remove/replace
SANITIZE_PATTERNS = [
    (r"carlos", "[TARGET_USER]"),
    (r"wiener", "[TEST_USER]"),
    (r"peter", "[TEST_PASS]"),
    (r"web-security-academy\.net", "[TARGET]"),
    (r"portswigger\.net", "[TARGET]"),
    (r"BURP-COLLABORATOR-SUBDOMAIN", "[CALLBACK_SERVER]"),
    (r"YOUR-EXPLOIT-SERVER", "[EXPLOIT_SERVER]"),
    (r"YOUR-LAB-ID", "[LAB_ID]"),
    (r"0a[a-f0-9]{20}", "[SESSION_ID]"),  # PortSwigger session IDs
]

# Map PortSwigger categories to our VulnType
CATEGORY_MAP = {
    "sql-injection": "sqli",
    "cross-site-scripting": "xss",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "file-path-traversal": "path_traversal",
    "access-control": "broken_access_control",
    "authentication": "auth_bypass",
    "csrf": "csrf",
    "os-command-injection": "rce",
    "server-side-template-injection": "ssti",
    "file-upload": "file_upload",
    "deserialization": "deserialization",
    "jwt": "jwt",
    "oauth": "oauth",
    "host-header": "host_header",
    "request-smuggling": "request_smuggling",
    "web-cache-poisoning": "cache_poisoning",
    "prototype-pollution": "prototype_pollution",
    "information-disclosure": "info_disclosure",
    "logic-flaws": "logic_flaw",
    "clickjacking": "clickjacking",
    "cors": "cors",
    "dom-based": "xss_dom",
    "websockets": "websockets",
    "graphql": "graphql",
    "nosql-injection": "nosql",
    "race-conditions": "race_condition",
    "llm-attacks": "llm_injection",
    "api-testing": "api",
    "web-cache-deception": "cache_deception",
}


def sanitize(text: str) -> str:
    """Remove PortSwigger-specific patterns."""
    if not text:
        return ""
    for pattern, replacement in SANITIZE_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def extract_techniques(labs: list[dict]) -> dict:
    """Extract techniques, payloads, and patterns from labs."""
    techniques = []
    payloads = set()
    indicators = set()
    bypasses = []
    
    for lab in labs:
        title = lab.get("title", "")
        solution = lab.get("solution", "")
        lab_payloads = lab.get("payloads", [])
        
        # Extract technique from title
        if title:
            techniques.append(sanitize(title))
        
        # Extract payloads (sanitized)
        for p in lab_payloads:
            p_clean = sanitize(p)
            if len(p_clean) > 3 and len(p_clean) < 200:
                # Skip generic words
                if p_clean.lower() not in ["admin", "password", "username", "login", "[target_user]", "[test_user]"]:
                    payloads.add(p_clean)
        
        # Look for bypass techniques in solution
        if solution:
            sol_lower = solution.lower()
            if "bypass" in sol_lower:
                # Extract the bypass technique
                for line in solution.split("\n"):
                    if "bypass" in line.lower():
                        bypasses.append(sanitize(line.strip()))
            
            # Look for indicators of success
            if "observe" in sol_lower or "verify" in sol_lower or "confirm" in sol_lower:
                for line in solution.split("\n"):
                    if any(w in line.lower() for w in ["observe", "verify", "confirm", "notice", "see that"]):
                        indicators.add(sanitize(line.strip()[:100]))
    
    return {
        "techniques": techniques,
        "payloads": list(payloads)[:30],  # Top 30
        "indicators": list(indicators)[:10],
        "bypasses": bypasses[:10],
    }


def generate_playbook(category: str, labs: list[dict]) -> str:
    """Generate a comprehensive playbook from lab data."""
    vuln_type = CATEGORY_MAP.get(category, category)
    data = extract_techniques(labs)
    
    # Group techniques by similarity
    technique_groups = defaultdict(list)
    for t in data["techniques"]:
        # Extract key words
        words = set(re.findall(r'\b\w+\b', t.lower()))
        key_words = words - {"a", "the", "in", "on", "to", "for", "with", "via", "using", "and", "or", "by"}
        
        # Group by first significant word or technique type
        if "blind" in words:
            technique_groups["Blind Techniques"].append(t)
        elif "bypass" in words:
            technique_groups["Bypass Techniques"].append(t)
        elif "dom" in words:
            technique_groups["DOM-based"].append(t)
        elif "stored" in words:
            technique_groups["Stored/Persistent"].append(t)
        elif "reflected" in words:
            technique_groups["Reflected"].append(t)
        elif "union" in words:
            technique_groups["UNION-based"].append(t)
        elif "error" in words:
            technique_groups["Error-based"].append(t)
        elif "time" in words or "delay" in words:
            technique_groups["Time-based"].append(t)
        elif "out-of-band" in words or "oob" in words:
            technique_groups["Out-of-band"].append(t)
        else:
            technique_groups["General"].append(t)
    
    # Build playbook
    md = f"""## {vuln_type.upper().replace('_', ' ')} Playbook
*Synthesized from {len(labs)} PortSwigger labs*

### Overview
This playbook covers {len(data['techniques'])} known attack techniques for {vuln_type}.

### Attack Techniques

"""
    
    for group, techniques in sorted(technique_groups.items()):
        if techniques:
            md += f"**{group}:**\n"
            for t in techniques[:8]:  # Limit per group
                md += f"- {t}\n"
            md += "\n"
    
    # Payloads section
    if data["payloads"]:
        md += "### Key Payloads\n"
        md += "```\n"
        for p in data["payloads"][:20]:
            md += f"{p}\n"
        md += "```\n\n"
    
    # Bypass techniques
    if data["bypasses"]:
        md += "### Bypass Techniques\n"
        for b in data["bypasses"]:
            if len(b) > 10:
                md += f"- {b[:150]}\n"
        md += "\n"
    
    # Indicators
    md += """### Indicators of Success
- Unexpected data in response
- Error messages revealing internal info
- Behavior change confirming injection
- Out-of-band callback received
- Access to unauthorized resources

### Testing Methodology
1. **Identify injection points** — forms, parameters, headers, cookies
2. **Test basic payloads** — start simple, escalate complexity
3. **Observe responses** — errors, timing, content changes
4. **Try bypasses** — encoding, alternative syntax, filter evasion
5. **Confirm impact** — data extraction, privilege escalation, RCE

"""
    
    return md


def main():
    # Load all labs
    all_labs_file = DATA_DIR / "all_labs.json"
    if not all_labs_file.exists():
        print(f"No data at {all_labs_file}")
        return
    
    with open(all_labs_file) as f:
        all_labs = json.load(f)
    
    # Group by category
    by_category = defaultdict(list)
    for lab in all_labs:
        cat = lab.get("category", "unknown")
        by_category[cat].append(lab)
    
    print(f"Synthesizing playbooks from {len(all_labs)} labs...")
    
    # Generate per-category playbooks
    for category, labs in sorted(by_category.items()):
        if len(labs) < 2:
            continue  # Skip tiny categories
        
        vuln_type = CATEGORY_MAP.get(category, category)
        playbook = generate_playbook(category, labs)
        
        outfile = OUTPUT_DIR / f"{vuln_type}_synthesized.md"
        with open(outfile, "w") as f:
            f.write(playbook)
        
        print(f"  {vuln_type}: {len(labs)} labs → {outfile.name}")
    
    print(f"\nDone! Synthesized playbooks in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
