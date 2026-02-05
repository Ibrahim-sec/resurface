#!/usr/bin/env python3
"""
Generate granular playbooks from scraped PortSwigger labs.
Creates per-lab markdown files in src/prompts/playbooks/labs/
"""

import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data" / "portswigger_labs"
PLAYBOOK_DIR = Path(__file__).parent.parent / "src" / "prompts" / "playbooks" / "labs"

# Map PortSwigger categories to VulnType enum values
CATEGORY_MAP = {
    "sql-injection": "sqli",
    "cross-site-scripting": "xss_reflected",  # Will refine per lab
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
    "llm-attacks": "llm_attack",
    "api-testing": "api",
    "web-cache-deception": "cache_deception",
}


def slugify(title: str) -> str:
    """Convert title to filename-safe slug."""
    slug = title.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug[:60]


def generate_playbook(lab: dict) -> str:
    """Generate markdown playbook for a lab."""
    title = lab.get("title", "Unknown")
    category = lab.get("category", "unknown")
    description = lab.get("description", "")
    solution = lab.get("solution", "")
    payloads = lab.get("payloads", [])
    
    vuln_type = CATEGORY_MAP.get(category, category)
    
    md = f"""## {title}

**Category:** {vuln_type}
**Difficulty:** {lab.get('difficulty', 'Unknown')}

### Description
{description}

### Solution Steps
{solution if solution else 'No solution available.'}

"""
    
    if payloads:
        md += "### Key Payloads\n"
        for p in payloads[:10]:
            # Escape backticks in payloads
            p_escaped = p.replace("`", "\\`")
            md += f"- `{p_escaped}`\n"
        md += "\n"
    
    md += f"""### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: {vuln_type}

---
*Source: PortSwigger Web Security Academy*
"""
    
    return md


def main():
    PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load all labs
    all_labs_file = DATA_DIR / "all_labs.json"
    if not all_labs_file.exists():
        print(f"No data found at {all_labs_file}")
        return
    
    with open(all_labs_file) as f:
        labs = json.load(f)
    
    print(f"Generating playbooks for {len(labs)} labs...")
    
    # Track by category
    by_category = {}
    
    for lab in labs:
        if not lab.get("title"):
            continue
        
        category = lab.get("category", "unknown")
        slug = slugify(lab["title"])
        filename = f"{category}_{slug}.md"
        
        playbook = generate_playbook(lab)
        
        outfile = PLAYBOOK_DIR / filename
        with open(outfile, "w") as f:
            f.write(playbook)
        
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(filename)
    
    # Generate index
    index_md = "# PortSwigger Lab Playbooks\n\n"
    index_md += f"Total: {len(labs)} playbooks\n\n"
    
    for cat, files in sorted(by_category.items()):
        index_md += f"## {cat} ({len(files)})\n"
        for f in sorted(files):
            name = f.replace(".md", "").replace(f"{cat}_", "").replace("_", " ").title()
            index_md += f"- [{name}]({f})\n"
        index_md += "\n"
    
    with open(PLAYBOOK_DIR / "INDEX.md", "w") as f:
        f.write(index_md)
    
    print(f"\nGenerated {len(labs)} playbooks in {PLAYBOOK_DIR}")
    print(f"Categories: {len(by_category)}")
    for cat, files in sorted(by_category.items(), key=lambda x: -len(x[1])):
        print(f"  {cat}: {len(files)}")


if __name__ == "__main__":
    main()
