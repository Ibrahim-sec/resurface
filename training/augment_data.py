#!/usr/bin/env python3
"""
Augment training data by generating variations using LLM.
"""
import json
import os
import random
from pathlib import Path
from together import Together

API_KEY = "acce4f60452145f207a99d269ef398458c6c8277db749380b48e5ecc37ca8dd6"
INPUT_FILE = Path(__file__).parent / "data" / "train_combined.jsonl"
OUTPUT_FILE = Path(__file__).parent / "data" / "train_augmented.jsonl"

client = Together(api_key=API_KEY)

VARIATION_PROMPT = """Take this security exploitation methodology and create a VARIATION of it.
Keep the same vulnerability type but:
1. Change the specific scenario details (different app context)
2. Vary the exploitation steps slightly (different approach order, alternative techniques)
3. Add or modify payloads
4. Keep the same format

ORIGINAL:
{original}

Generate a realistic variation. Output ONLY the new example in the same format, nothing else."""

def load_examples():
    examples = []
    with open(INPUT_FILE) as f:
        for line in f:
            examples.append(json.loads(line))
    return examples

def generate_variation(example: dict) -> dict | None:
    """Generate a variation of an existing example."""
    original = example['messages'][1]['content']  # Assistant response
    
    try:
        response = client.chat.completions.create(
            model="meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
            messages=[
                {"role": "system", "content": "You are an expert security researcher creating training data for a vulnerability detection model."},
                {"role": "user", "content": VARIATION_PROMPT.format(original=original)}
            ],
            max_tokens=1500,
            temperature=0.8
        )
        
        new_response = response.choices[0].message.content
        
        # Keep the same user prompt but with slight modification
        user_msg = example['messages'][0]['content']
        
        return {
            "messages": [
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": new_response}
            ]
        }
    except Exception as e:
        print(f"Error: {e}")
        return None

def main():
    examples = load_examples()
    print(f"Loaded {len(examples)} examples")
    
    # Sample examples to augment (don't augment all - expensive)
    sample_size = min(100, len(examples))
    to_augment = random.sample(examples, sample_size)
    
    augmented = []
    for i, ex in enumerate(to_augment):
        print(f"Generating variation {i+1}/{sample_size}...")
        variation = generate_variation(ex)
        if variation:
            augmented.append(variation)
    
    print(f"Generated {len(augmented)} variations")
    
    # Combine original + augmented
    combined = examples + augmented
    
    with open(OUTPUT_FILE, 'w') as f:
        for ex in combined:
            f.write(json.dumps(ex) + '\n')
    
    print(f"Saved {len(combined)} total examples to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
