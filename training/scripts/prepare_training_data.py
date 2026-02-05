#!/usr/bin/env python3
"""
Convert PortSwigger playbooks to Vertex AI fine-tuning format.
Splits into train/test sets and creates JSONL files.
"""

import json
import random
import re
from pathlib import Path
from collections import defaultdict

LABS_DIR = Path("/root/resurface/src/prompts/playbooks/labs")
OUTPUT_DIR = Path("/root/resurface/training/data")

def parse_playbook(filepath: Path) -> dict:
    """Parse a playbook markdown file into structured data."""
    content = filepath.read_text()
    
    # Extract title
    title_match = re.search(r'^## (.+)$', content, re.MULTILINE)
    title = title_match.group(1) if title_match else filepath.stem
    
    # Extract category
    cat_match = re.search(r'\*\*Category:\*\*\s*(\S+)', content)
    category = cat_match.group(1) if cat_match else "unknown"
    
    # Extract difficulty
    diff_match = re.search(r'\*\*Difficulty:\*\*\s*(\S+)', content)
    difficulty = diff_match.group(1) if diff_match else "Unknown"
    
    # Extract description
    desc_match = re.search(r'### Description\n(.+?)(?=\n###|\n\*\*)', content, re.DOTALL)
    description = desc_match.group(1).strip() if desc_match else ""
    
    # Extract solution steps
    steps_match = re.search(r'### Solution Steps\n(.+?)(?=\n###|\n\*\*)', content, re.DOTALL)
    steps = steps_match.group(1).strip() if steps_match else ""
    
    # Extract payloads
    payloads_match = re.search(r'### Key Payloads\n(.+?)(?=\n###|\n\*\*)', content, re.DOTALL)
    payloads = payloads_match.group(1).strip() if payloads_match else ""
    
    # Extract indicators
    indicators_match = re.search(r'### Indicators of Success\n(.+?)(?=\n---|\Z)', content, re.DOTALL)
    indicators = indicators_match.group(1).strip() if indicators_match else ""
    
    return {
        "title": title,
        "category": category,
        "difficulty": difficulty,
        "description": description,
        "steps": steps,
        "payloads": payloads,
        "indicators": indicators,
        "filename": filepath.name
    }

def create_training_example(playbook: dict) -> dict:
    """Create a Vertex AI training example from a playbook."""
    
    # User prompt: describe the vulnerability scenario
    user_prompt = f"""You are a security researcher testing a web application for vulnerabilities.

**Vulnerability Type:** {playbook['category']}
**Scenario:** {playbook['description']}

Generate a step-by-step exploitation methodology for this vulnerability. Include:
1. Detailed exploitation steps
2. Key payloads to use
3. Indicators that confirm successful exploitation"""

    # Model response: the playbook content
    model_response = f"""## Exploitation Methodology: {playbook['title']}

### Step-by-Step Exploitation
{playbook['steps']}

### Key Payloads
{playbook['payloads']}

### Success Indicators
{playbook['indicators']}"""

    return {
        "messages": [
            {"role": "user", "content": user_prompt},
            {"role": "model", "content": model_response}
        ]
    }

def create_eval_example(playbook: dict) -> dict:
    """Create an evaluation example (input + expected output for scoring)."""
    return {
        "id": playbook['filename'],
        "category": playbook['category'],
        "difficulty": playbook['difficulty'],
        "input": {
            "vuln_type": playbook['category'],
            "description": playbook['description']
        },
        "expected": {
            "title": playbook['title'],
            "steps": playbook['steps'],
            "payloads": playbook['payloads'],
            "indicators": playbook['indicators']
        }
    }

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Parse all playbooks
    playbooks = []
    for md_file in sorted(LABS_DIR.glob("*.md")):
        if md_file.name == "INDEX.md":
            continue
        playbook = parse_playbook(md_file)
        if playbook['steps']:  # Only include if it has steps
            playbooks.append(playbook)
    
    print(f"Parsed {len(playbooks)} playbooks")
    
    # Group by category for stratified split
    by_category = defaultdict(list)
    for pb in playbooks:
        by_category[pb['category']].append(pb)
    
    print(f"Categories: {len(by_category)}")
    for cat, items in sorted(by_category.items()):
        print(f"  {cat}: {len(items)}")
    
    # Stratified split: 1 per category for test, rest for train
    train_set = []
    test_set = []
    
    random.seed(42)  # Reproducible
    for cat, items in by_category.items():
        random.shuffle(items)
        if len(items) > 1:
            test_set.append(items[0])  # 1 for test
            train_set.extend(items[1:])  # Rest for train
        else:
            train_set.append(items[0])  # If only 1, use for training
    
    print(f"\nSplit: {len(train_set)} train, {len(test_set)} test")
    
    # Create training JSONL (Vertex format)
    train_jsonl = OUTPUT_DIR / "train.jsonl"
    with open(train_jsonl, 'w') as f:
        for pb in train_set:
            example = create_training_example(pb)
            f.write(json.dumps(example) + '\n')
    print(f"Wrote {train_jsonl}")
    
    # Create eval JSONL
    eval_jsonl = OUTPUT_DIR / "eval.jsonl"
    with open(eval_jsonl, 'w') as f:
        for pb in test_set:
            example = create_eval_example(pb)
            f.write(json.dumps(example) + '\n')
    print(f"Wrote {eval_jsonl}")
    
    # Create full dataset (for reference)
    full_jsonl = OUTPUT_DIR / "full.jsonl"
    with open(full_jsonl, 'w') as f:
        for pb in playbooks:
            example = create_training_example(pb)
            f.write(json.dumps(example) + '\n')
    print(f"Wrote {full_jsonl}")
    
    # Stats
    print(f"\n=== Training Data Ready ===")
    print(f"Train examples: {len(train_set)}")
    print(f"Test examples: {len(test_set)}")
    print(f"Total: {len(playbooks)}")
    print(f"\nFiles:")
    print(f"  {train_jsonl} - Upload to Vertex AI")
    print(f"  {eval_jsonl} - For evaluation")
    print(f"  {full_jsonl} - Complete dataset")

if __name__ == "__main__":
    main()
