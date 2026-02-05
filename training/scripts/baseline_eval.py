#!/usr/bin/env python3
"""
Evaluate baseline Gemini performance on held-out test set.
Run BEFORE fine-tuning to establish comparison baseline.
"""

import json
import time
import os
from pathlib import Path
from datetime import datetime

from google import genai

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
    """Create the prompt for Gemini."""
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
    
    # Extract key terms from expected
    step_keywords = [w for w in expected_steps.split() if len(w) > 4][:20]
    payload_keywords = [w for w in expected_payloads.split() if len(w) > 4][:15]
    indicator_keywords = [w for w in expected_indicators.split() if len(w) > 4][:10]
    
    # Count matches
    step_matches = sum(1 for kw in step_keywords if kw in response_lower)
    payload_matches = sum(1 for kw in payload_keywords if kw in response_lower)
    indicator_matches = sum(1 for kw in indicator_keywords if kw in response_lower)
    
    # Calculate scores (percentage of keywords found)
    step_score = step_matches / max(len(step_keywords), 1)
    payload_score = payload_matches / max(len(payload_keywords), 1)
    indicator_score = indicator_matches / max(len(indicator_keywords), 1)
    
    # Overall score (weighted)
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

def run_baseline_eval(api_key: str, model_name: str = "gemini-2.0-flash"):
    """Run baseline evaluation."""
    client = genai.Client(api_key=api_key)
    
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
            response = client.models.generate_content(
                model=model_name,
                contents=prompt
            )
            response_text = response.text
            
            # Score the response
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
            
            # Rate limiting
            time.sleep(0.5)
            
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({
                "id": example['id'],
                "category": example['category'],
                "error": str(e)
            })
    
    # Summary
    successful = [r for r in results if 'scores' in r]
    avg_score = total_score / len(successful) if successful else 0
    
    print("\n" + "=" * 60)
    print(f"BASELINE EVALUATION COMPLETE")
    print(f"Model: {model_name}")
    print(f"Examples: {len(examples)} ({len(successful)} successful)")
    print(f"Average Score: {avg_score:.1%}")
    print("=" * 60)
    
    # Category breakdown
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
    
    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_short = model_name.replace("/", "_").replace("models_", "")
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
        print("Usage: python baseline_eval.py <GOOGLE_API_KEY> [model_name]")
        print("Models: gemini-2.0-flash, gemini-2.5-flash, gemini-2.5-pro")
        sys.exit(1)
    
    api_key = sys.argv[1]
    model_name = sys.argv[2] if len(sys.argv) > 2 else "gemini-2.0-flash"
    
    run_baseline_eval(api_key, model_name)
