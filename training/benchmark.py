#!/usr/bin/env python3
"""
Benchmark: Base vs Fine-tuned model on eval set
"""
import json
import time
from together import Together
from difflib import SequenceMatcher

# Config
API_KEY = "acce4f60452145f207a99d269ef398458c6c8277db749380b48e5ecc37ca8dd6"
BASE_MODEL = "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo"
FINETUNED_MODEL = "leetibrahim_857e/Meta-Llama-3.1-8B-Instruct-Reference-resurface-v2-13c75146"
EVAL_FILE = "data/eval.jsonl"

client = Together(api_key=API_KEY)

def load_eval_data():
    examples = []
    with open(EVAL_FILE) as f:
        for line in f:
            ex = json.loads(line)
            # Handle both formats
            if "messages" in ex:
                messages = ex["messages"]
                if len(messages) >= 2:
                    prompt = messages[0]["content"]
                    expected = messages[1]["content"]
                    examples.append({"prompt": prompt, "expected": expected})
            elif "input" in ex and "expected" in ex:
                # Eval format: input/expected structure
                inp = ex["input"]
                exp = ex["expected"]
                prompt = f"""You are a security researcher testing a web application for vulnerabilities.

**Vulnerability Type:** {inp.get('vuln_type', 'unknown')}
**Scenario:** {inp.get('description', '')}

Generate a step-by-step exploitation methodology for this vulnerability. Include:
1. Detailed exploitation steps
2. Key payloads to use
3. Indicators that confirm successful exploitation"""
                
                expected = f"""## Exploitation Methodology: {exp.get('title', '')}

### Step-by-Step Exploitation
{exp.get('steps', '')}

### Key Payloads
{exp.get('payloads', '')}

### Success Indicators
{exp.get('indicators', '')}"""
                examples.append({"prompt": prompt, "expected": expected})
    return examples

def generate(model: str, prompt: str) -> str:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.1
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"ERROR: {e}"

def score_response(generated: str, expected: str) -> float:
    """
    Score based on:
    1. Key section presence (Steps, Payloads, Indicators)
    2. Content similarity
    """
    score = 0.0
    gen_lower = generated.lower()
    exp_lower = expected.lower()
    
    # Check for key sections (40% weight)
    sections = ["step", "payload", "indicator", "exploit"]
    section_hits = sum(1 for s in sections if s in gen_lower and s in exp_lower)
    score += (section_hits / len(sections)) * 0.4
    
    # Content similarity (60% weight)
    similarity = SequenceMatcher(None, gen_lower[:1000], exp_lower[:1000]).ratio()
    score += similarity * 0.6
    
    return round(score * 100, 1)

def run_benchmark():
    examples = load_eval_data()
    print(f"Loaded {len(examples)} eval examples\n")
    
    base_scores = []
    ft_scores = []
    
    for i, ex in enumerate(examples):
        print(f"[{i+1}/{len(examples)}] Evaluating...")
        
        # Base model
        base_resp = generate(BASE_MODEL, ex["prompt"])
        base_score = score_response(base_resp, ex["expected"])
        base_scores.append(base_score)
        
        time.sleep(0.5)  # Rate limit
        
        # Fine-tuned model
        ft_resp = generate(FINETUNED_MODEL, ex["prompt"])
        ft_score = score_response(ft_resp, ex["expected"])
        ft_scores.append(ft_score)
        
        print(f"    Base: {base_score}% | Fine-tuned: {ft_score}%")
        time.sleep(0.5)
    
    # Summary
    print("\n" + "="*50)
    print("BENCHMARK RESULTS")
    print("="*50)
    base_avg = sum(base_scores) / len(base_scores)
    ft_avg = sum(ft_scores) / len(ft_scores)
    improvement = ft_avg - base_avg
    
    print(f"Base Model Avg:       {base_avg:.1f}%")
    print(f"Fine-tuned Model Avg: {ft_avg:.1f}%")
    print(f"Improvement:          {improvement:+.1f}%")
    print("="*50)
    
    # Save results
    results = {
        "base_model": BASE_MODEL,
        "finetuned_model": FINETUNED_MODEL,
        "num_examples": len(examples),
        "base_avg": base_avg,
        "finetuned_avg": ft_avg,
        "improvement": improvement,
        "base_scores": base_scores,
        "finetuned_scores": ft_scores
    }
    with open("benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to benchmark_results.json")

if __name__ == "__main__":
    run_benchmark()
