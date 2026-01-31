#!/usr/bin/env python3
"""
Expanded HackerOne scraper — fetches 50+ full-disclosure reports
by paginating through the GraphQL Hacktivity index and downloading each report.
Uses curl for reliable HTTPS requests.
"""
import json
import os
import subprocess
import sys
import time

GRAPHQL_URL = "https://hackerone.com/graphql"
REPORT_URL = "https://hackerone.com/reports/{}.json"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports")
RATE_LIMIT = 0.4
TARGET_REPORTS = 60
MAX_PAGES = 50
PER_PAGE = 50

GRAPHQL_QUERY_TEMPLATE = 'query {{ search(index: CompleteHacktivityReportIndex, query_string: "*", first: {first}{after_clause}) {{ total_count edges {{ cursor node {{ ... on HacktivityDocument {{ _id }} }} }} }} }}'


def curl_json(url, post_data=None, timeout=20):
    """Make HTTP request via curl and return parsed JSON."""
    cmd = [
        "curl", "-s", "--max-time", str(timeout),
        "-H", "User-Agent: Resurface/1.0",
        "-H", "Content-Type: application/json",
    ]
    if post_data:
        cmd += ["-d", json.dumps(post_data)]
    cmd.append(url)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        if result.returncode != 0:
            return None
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        print(f"  curl error: {e}", flush=True)
        return None


def get_hacktivity_ids():
    """Paginate through GraphQL to collect report IDs."""
    all_ids = []
    cursor = ""
    
    for page in range(MAX_PAGES):
        after_clause = f', after: "{cursor}"' if cursor else ""
        query = GRAPHQL_QUERY_TEMPLATE.format(first=PER_PAGE, after_clause=after_clause)
        
        result = curl_json(GRAPHQL_URL, {"query": query})
        
        if not result or "errors" in result:
            print(f"  GraphQL error on page {page + 1}, stopping", flush=True)
            if result and "errors" in result:
                print(f"  Errors: {result['errors']}", flush=True)
            break
        
        edges = result.get("data", {}).get("search", {}).get("edges", [])
        if not edges:
            print(f"  No more edges on page {page + 1}", flush=True)
            break
        
        for edge in edges:
            _id = edge.get("node", {}).get("_id")
            if _id:
                all_ids.append(str(_id))
        
        cursor = edges[-1].get("cursor", "")
        total = result.get("data", {}).get("search", {}).get("total_count", "?")
        print(f"  Page {page + 1}: got {len(edges)} IDs (total: {total}, collected: {len(all_ids)})", flush=True)
        
        time.sleep(RATE_LIMIT)
    
    # Deduplicate
    seen = set()
    unique = []
    for _id in all_ids:
        if _id not in seen:
            seen.add(_id)
            unique.append(_id)
    
    print(f"\nCollected {len(unique)} unique IDs", flush=True)
    return unique


def fetch_report(report_id):
    """Download a report, return dict if full-disclosure with good content."""
    cache_path = os.path.join(DATA_DIR, f"{report_id}.json")
    
    # Already cached
    if os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                data = json.load(f)
            if data.get("visibility") == "full":
                vi = data.get("vulnerability_information", "") or ""
                if len(vi) > 200:
                    return data
        except:
            pass
        return None
    
    url = REPORT_URL.format(report_id)
    data = curl_json(url, timeout=15)
    
    if not data:
        return None
    
    if data.get("visibility") != "full":
        return None
    
    vi = data.get("vulnerability_information", "") or ""
    if len(vi) <= 200:
        return None
    
    # Save
    with open(cache_path, "w") as f:
        json.dump(data, f, indent=2)
    
    return data


def count_existing():
    """Count existing valid full-disclosure reports."""
    count = 0
    for fname in os.listdir(DATA_DIR):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(DATA_DIR, fname)) as f:
                d = json.load(f)
            if d.get("visibility") == "full":
                vi = d.get("vulnerability_information", "") or ""
                if len(vi) > 200:
                    count += 1
        except:
            pass
    return count


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    
    existing = count_existing()
    print(f"Existing valid reports: {existing}", flush=True)
    print(f"Target: {TARGET_REPORTS} total\n", flush=True)
    
    if existing >= TARGET_REPORTS:
        print(f"Already have {existing} reports, target met!", flush=True)
        return
    
    # Phase 1: Get IDs
    print("Phase 1: Fetching report IDs from GraphQL...", flush=True)
    ids = get_hacktivity_ids()
    
    if not ids:
        print("No IDs fetched, exiting.", flush=True)
        sys.exit(1)
    
    # Phase 2: Fetch reports
    print(f"\nPhase 2: Fetching individual reports...", flush=True)
    found = existing
    checked = 0
    new_found = 0
    
    for rid in ids:
        if found >= TARGET_REPORTS:
            break
        
        checked += 1
        report = fetch_report(rid)
        
        if report:
            title = report.get("title", "Unknown")[:55]
            severity = report.get("severity_rating", "none")
            team = report.get("team", {}).get("handle", "?")
            found += 1
            new_found += 1
            print(f"  ✅ [{found}] {rid} | {severity} | {team} | {title}", flush=True)
        
        if checked % 20 == 0:
            print(f"  ... checked {checked}/{len(ids)}, found {found} total ({new_found} new)", flush=True)
        
        time.sleep(RATE_LIMIT)
    
    total_files = len([f for f in os.listdir(DATA_DIR) if f.endswith(".json")])
    print(f"\n{'='*60}", flush=True)
    print(f"Scrape complete!", flush=True)
    print(f"  Checked: {checked} IDs", flush=True)
    print(f"  New reports saved: {new_found}", flush=True)
    print(f"  Total valid reports: {found}", flush=True)
    print(f"  Total files in data/reports/: {total_files}", flush=True)
    print(f"{'='*60}", flush=True)


if __name__ == "__main__":
    main()
