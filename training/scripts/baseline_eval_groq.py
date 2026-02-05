#!/usr/bin/env python3
"""
Evaluate baseline Groq/Llama performance on held-out test set.
"""

import json
import time
import os
from pathlib import Path
from datetime import datetime

from groq import Groq

EVAL_FILE = Path("/root/resurface/training/data/eval.jsonl")
RESULTS_DIR = Path("/root/resurface/training/eval")

def load_eval_data():
    """Load evaluation examples."""
    examples = []
    with open(EVAL_FILE) as f:
        for line in f:
            examples.append(json.loads(line))
    return examples

def generate_prompt(example: dict) -> str:
    """Create the prompt."""
    return f"""You are a security researcher testing a web application for vulnerabilities.

**Vulnerability Type:** {example['input']['vuln_type']}
**Scenario:** {example['input']['description']}

Generate a step-by-step exploitation methodology for this vulnerability. Include:
1. Detailed exploitation steps (numbered)
2. Key payloads to use (as a bullet list)
3. Indicators that confirm successful exploitation (as a bullet list)

Be specific and technical. Include actual payloads and HTTP requests where relevant."""

def score_response(response: str, expected: dict) -> dict:
    """Score the model response against expected output."""
    response_lower = response.lower()
    expected_steps = expected['steps'].lower()
    expected_payloads = expected['payloads'].lower()
    expected_indicators = expected['indicators'].lower()
    
    step_keywords = [w for w in expected_steps.split() if len(w) > 4][:20]
    payload_keywords = [w for w in expected_payloads.split() if len(w) > 4][:15]
    indicator_keywords = [w for w in expected_indicators.split() if len(w) > 4][:10]
    
    step_matches = sum(1 for kw in step_keywords if kw in response_lower)
    payload_matches = sum(1 for kw in payload_keywords if kw in response_lower)
    indicator_matches = sum(1 for kw in indicator_keywords if kw in response_lower)
    
    step_score = step_matches / max(len(step_keywords), 1)
    payload_score = payload_matches / max(len(payload_keywords), 1)
    indicator_score = indicator_matches / max(len(indicator_keywords), 1)
    
    overall = (step_score * 0.5) + (payload_score * 0.3) + (indicator_score * 0.2)
    
    return {
        "step_score": round(step_score, 3),
        "payload_score": round(payload_score, 3),
        "indicator_score": round(indicator_score, 3),
        "overall": round(overall, 3),
        "step_matches": f"{step_matches}/{len(step_keywords)}",
        "payload_matches": f"{payload_matches}/{len(payload_keywords)}",
        "indicator_matches": f"{indicator_matches}/{len(indicator_keywords)}"
    }

def run_baseline_eval(api_key: str, model_name: str = "llama-3.3-70b-versatile"):
    """Run baseline evaluation with Groq."""
    client = Groq(api_key=api_key)
    
    examples = load_eval_data()
    print(f"Loaded {len(examples)} evaluation examples")
    print(f"Model: {model_name}")
    print("=" * 60)
    
    results = []
    total_score = 0
    
    for i, example in enumerate(examples):
        print(f"\n[{i+1}/{len(examples)}] {example['category']} - {example['id'][:50]}...")
        
        prompt = generate_prompt(example)
        
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.3
            )
            response_text = response.choices[0].message.content
            
            scores = score_response(response_text, example['expected'])
            total_score += scores['overall']
            
            print(f"  Steps: {scores['step_score']:.0%} | Payloads: {scores['payload_score']:.0%} | Indicators: {scores['indicator_score']:.0%} | Overall: {scores['overall']:.0%}")
            
            results.append({
                "id": example['id'],
                "category": example['category'],
                "difficulty": example['difficulty'],
                "scores": scores,
                "response_length": len(response_text),
                "response_preview": response_text[:500] + "..." if len(response_text) > 500 else response_text
            })
            
            time.sleep(0.5)  # Rate limiting
            
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({
                "id": example['id'],
                "category": example['category'],
                "error": str(e)
            })
            time.sleep(2)  # Back off on error
    
    successful = [r for r in results if 'scores' in r]
    avg_score = total_score / len(successful) if successful else 0
    
    print("\n" + "=" * 60)
    print(f"BASELINE EVALUATION COMPLETE")
    print(f"Model: {model_name}")
    print(f"Examples: {len(examples)} ({len(successful)} successful)")
    print(f"Average Score: {avg_score:.1%}")
    print("=" * 60)
    
    by_category = {}
    for r in results:
        cat = r['category']
        if 'scores' in r:
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(r['scores']['overall'])
    
    print("\nBy Category:")
    for cat, scores in sorted(by_category.items(), key=lambda x: -sum(x[1])/len(x[1])):
        avg = sum(scores) / len(scores)
        print(f"  {cat}: {avg:.1%}")
    
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_short = model_name.replace("/", "_")
    results_file = RESULTS_DIR / f"baseline_{model_short}_{timestamp}.json"
    
    with open(results_file, 'w') as f:
        json.dump({
            "model": model_name,
            "timestamp": timestamp,
            "num_examples": len(examples),
            "num_successful": len(successful),
            "average_score": avg_score,
            "by_category": {k: sum(v)/len(v) for k, v in by_category.items()},
            "results": results
        }, f, indent=2)
    
    print(f"\nResults saved to: {results_file}")
    return avg_score, results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python baseline_eval_groq.py <GROQ_API_KEY> [model_name]")
        print("Models: llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768")
        sys.exit(1)
    
    api_key = sys.argv[1]
    model_name = sys.argv[2] if len(sys.argv) > 2 else "llama-3.3-70b-versatile"
    
    run_baseline_eval(api_key, model_name)
