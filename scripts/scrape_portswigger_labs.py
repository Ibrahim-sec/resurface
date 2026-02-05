#!/usr/bin/env python3
"""
Scrape PortSwigger Web Security Academy labs and solutions.
Uses sitemap to find all lab URLs.
"""

import json
import re
import time
from pathlib import Path
import httpx
from bs4 import BeautifulSoup

BASE_URL = "https://portswigger.net"
SITEMAP_URL = "https://portswigger.net/sitemap.xml"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "portswigger_labs"


def get_category(url: str) -> str:
    """Extract category from lab URL."""
    match = re.search(r"/web-security/([^/]+)/", url)
    if match:
        return match.group(1)
    return "unknown"


def get_all_lab_urls(client: httpx.Client) -> list[str]:
    """Get all lab URLs from sitemap."""
    print("Fetching sitemap...")
    
    resp = client.get(SITEMAP_URL, timeout=60)
    resp.raise_for_status()
    
    soup = BeautifulSoup(resp.text, "xml")
    urls = []
    
    for loc in soup.find_all("loc"):
        url = loc.get_text(strip=True)
        if "/web-security/" in url and "/lab-" in url:
            urls.append(url)
    
    print(f"Found {len(urls)} lab URLs in sitemap")
    return urls


def get_lab_solution(client: httpx.Client, url: str) -> dict:
    """Fetch solution for a specific lab."""
    lab = {
        "url": url,
        "category": get_category(url),
    }
    
    try:
        resp = client.get(url, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        lab["error"] = str(e)
        return lab
    
    soup = BeautifulSoup(resp.text, "html.parser")
    
    # Get title from h1
    h1 = soup.find("h1")
    if h1:
        lab["title"] = h1.get_text(strip=True)
        if lab["title"].startswith("Lab:"):
            lab["title"] = lab["title"][4:].strip()
    
    # Get main content div
    main = soup.find("div", class_="is-lab")
    if not main:
        main = soup.find("main") or soup
    
    # Get description - first <p> in main content area that isn't empty
    for p in main.find_all("p", limit=5):
        text = p.get_text(strip=True)
        if len(text) > 50 and "Burp" not in text:
            lab["description"] = text
            break
    
    # Get solution from <details> element
    details = soup.find("details")
    if details:
        # Get content inside details (after summary)
        summary = details.find("summary")
        if summary:
            summary.decompose()  # Remove summary from tree
        
        # Get ordered list items
        ol = details.find("ol")
        if ol:
            steps = []
            for li in ol.find_all("li", recursive=False):
                step_text = li.get_text(strip=True, separator=" ")
                if step_text:
                    steps.append(step_text)
            lab["solution_steps"] = steps
            lab["solution"] = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        else:
            # Fallback to raw text
            lab["solution"] = details.get_text(strip=True, separator="\n")
    
    # Get code snippets (payloads)
    code_blocks = soup.find_all("code")
    payloads = []
    for c in code_blocks:
        text = c.get_text(strip=True)
        # Filter out noise
        if len(text) > 3 and len(text) < 500:
            if text not in payloads:
                payloads.append(text)
    if payloads:
        lab["payloads"] = payloads[:15]  # Limit
    
    return lab


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    client = httpx.Client(
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        follow_redirects=True,
    )
    
    urls = get_all_lab_urls(client)
    if not urls:
        print("No labs found!")
        return
    
    all_labs = []
    
    for i, url in enumerate(urls):
        slug = url.split("/")[-1][:35]
        print(f"[{i+1}/{len(urls)}] {slug}...")
        
        lab = get_lab_solution(client, url)
        all_labs.append(lab)
        time.sleep(0.15)
        
        if (i + 1) % 50 == 0:
            with open(OUTPUT_DIR / "all_labs_partial.json", "w") as f:
                json.dump(all_labs, f, indent=2)
            print(f"  Checkpoint: {i+1}/{len(urls)}")
    
    # Group by category
    by_category = {}
    for lab in all_labs:
        cat = lab.get("category", "unknown")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(lab)
    
    # Save per category
    for category, labs in by_category.items():
        outfile = OUTPUT_DIR / f"{category}.json"
        with open(outfile, "w") as f:
            json.dump(labs, f, indent=2)
        print(f"Saved {len(labs)} labs → {category}.json")
    
    # Save all
    with open(OUTPUT_DIR / "all_labs.json", "w") as f:
        json.dump(all_labs, f, indent=2)
    
    # Summary
    print(f"\n=== DONE ===")
    print(f"Total: {len(all_labs)} labs")
    for cat, labs in sorted(by_category.items(), key=lambda x: -len(x[1])):
        solved = sum(1 for l in labs if l.get("solution"))
        print(f"  {cat}: {len(labs)} ({solved} with solutions)")
    
    client.close()


if __name__ == "__main__":
    main()
