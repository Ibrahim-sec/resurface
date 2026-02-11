#!/usr/bin/env python3
"""
Generate more training data from all available playbooks.
"""
import json
import re
from pathlib import Path

LABS_DIR = Path(__file__).parent.parent / "src" / "prompts" / "playbooks" / "labs"
OUTPUT_FILE = Path(__file__).parent / "data" / "train_expanded.jsonl"

DEFAULT_INDICATORS = """- Successful exploitation confirmed by response changes
- Unauthorized access or data disclosure
- Application behavior matches expected exploit outcome"""

def extract_sections(content: str) -> dict:
    """Extract sections from playbook markdown."""
    sections = {}
    
    # Title (## Title or # Title)
    title_match = re.search(r'^##?\s+(.+)$', content, re.MULTILINE)
    if title_match:
        sections['title'] = title_match.group(1).strip()
    
    # Category/Vuln type
    cat_match = re.search(r'\*\*Category:?\*\*\s*`?([^`\n]+)`?', content)
    if cat_match:
        sections['category'] = cat_match.group(1).strip()
    
    # Description/Scenario
    desc_match = re.search(r'###?\s*Description\s*\n(.+?)(?=\n###|\n\*\*|$)', content, re.DOTALL)
    if desc_match:
        sections['description'] = desc_match.group(1).strip()
    
    # Steps (Solution Steps or Steps)
    steps_match = re.search(r'###?\s*(?:Solution\s*)?Steps?\s*\n(.*?)(?=\n###|$)', content, re.DOTALL | re.IGNORECASE)
    if steps_match:
        sections['steps'] = steps_match.group(1).strip()
    
    # Payloads
    payload_match = re.search(r'###?\s*(?:Key\s*)?Payloads?\s*\n(.*?)(?=\n###|$)', content, re.DOTALL | re.IGNORECASE)
    if payload_match:
        sections['payloads'] = payload_match.group(1).strip()
    
    # Indicators
    ind_match = re.search(r'###?\s*(?:Indicators?\s*of\s*)?Success\s*\n(.*?)(?=\n###|\n---|$)', content, re.DOTALL | re.IGNORECASE)
    if ind_match:
        sections['indicators'] = ind_match.group(1).strip()
    
    return sections

def create_training_example(sections: dict) -> dict:
    """Create a training example from extracted sections."""
    title = sections.get('title', 'Unknown Vulnerability')
    category = sections.get('category', 'unknown')
    description = sections.get('description', title)
    steps = sections.get('steps', '')
    payloads = sections.get('payloads', '')
    indicators = sections.get('indicators', '')
    
    if not steps:
        return None
    
    # User prompt
    user_content = f"""You are a security researcher testing a web application for vulnerabilities.

**Vulnerability Type:** {category}
**Scenario:** {description}

Generate a step-by-step exploitation methodology for this vulnerability. Include:
1. Detailed exploitation steps
2. Key payloads to use
3. Indicators that confirm successful exploitation"""

    # Assistant response
    assistant_content = f"""## Exploitation Methodology: {title}

### Step-by-Step Exploitation
{steps}

### Key Payloads
{payloads if payloads else '- See steps above for specific payloads'}

### Success Indicators
{indicators if indicators else DEFAULT_INDICATORS}"""

    return {
        "messages": [
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content}
        ]
    }

def main():
    examples = []
    
    # Process all lab playbooks
    for lab_file in LABS_DIR.glob("*.md"):
        try:
            content = lab_file.read_text()
            sections = extract_sections(content)
            example = create_training_example(sections)
            if example:
                examples.append(example)
        except Exception as e:
            print(f"Error processing {lab_file.name}: {e}")
    
    print(f"Generated {len(examples)} training examples from labs")
    
    # Also load existing training data
    existing_file = Path(__file__).parent / "data" / "train_together.jsonl"
    existing = []
    if existing_file.exists():
        with open(existing_file) as f:
            for line in f:
                existing.append(json.loads(line))
        print(f"Loaded {len(existing)} existing examples")
    
    # Combine and dedupe (by user content hash)
    seen = set()
    combined = []
    
    for ex in existing + examples:
        key = hash(ex['messages'][0]['content'][:200])
        if key not in seen:
            seen.add(key)
            combined.append(ex)
    
    print(f"Total unique examples: {len(combined)}")
    
    # Write output
    with open(OUTPUT_FILE, 'w') as f:
        for ex in combined:
            f.write(json.dumps(ex) + '\n')
    
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
