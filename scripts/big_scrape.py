#!/usr/bin/env python3
"""
Expanded HackerOne scraper — fetches 50+ full-disclosure reports
by paginating through the GraphQL Hacktivity index and downloading each report.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

GRAPHQL_URL = "https://hackerone.com/graphql"
REPORT_URL = "https://hackerone.com/reports/{}.json"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports")
RATE_LIMIT = 0.35
TARGET_REPORTS = 60
MAX_PAGES = 50
PER_PAGE = 50
USER_AGENT = "Resurface/1.0"

GRAPHQL_QUERY = """query {{
    search(
        index: CompleteHacktivityReportIndex,
        query_string: "*",
        first: {first}{after_clause}
    ) {{
        total_count
        edges {{
            cursor
            node {{
                ... on HacktivityDocument {{
                    _id
                }}
            }}
        }}
    }}
}}"""


def make_request(url, data=None):
    """Make an HTTP request and return parsed JSON or None."""
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        if data:
            req.data = json.dumps(data).encode()
        resp = urllib.request.urlopen(req, timeout=20)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"  Rate limited, sleeping 5s...")
            time.sleep(5)
            return make_request(url, data)  # retry once
        print(f"  HTTP {e.code} for {url}")
        return None
    except Exception as e:
        print(f"  Error: {e}")
        return None


def get_hacktivity_ids():
    """Paginate through GraphQL to collect report IDs."""
    all_ids = []
    cursor = ""
    
    for page in range(MAX_PAGES):
        after_clause = f', after: "{cursor}"' if cursor else ""
        query = GRAPHQL_QUERY.format(first=PER_PAGE, after_clause=after_clause)
        
        result = make_request(GRAPHQL_URL, {"query": query})
        
        if not result or "errors" in result:
            print(f"  GraphQL error on page {page + 1}, stopping pagination")
            if result and "errors" in result:
                print(f"  Errors: {result['errors']}")
            break
        
        edges = result.get("data", {}).get("search", {}).get("edges", [])
        if not edges:
            print(f"  No more edges on page {page + 1}")
            break
        
        for edge in edges:
            _id = edge.get("node", {}).get("_id")
            if _id:
                all_ids.append(str(_id))
        
        cursor = edges[-1].get("cursor", "")
        total = result.get("data", {}).get("search", {}).get("total_count", "?")
        print(f"  Page {page + 1}: got {len(edges)} IDs (total available: {total}, collected: {len(all_ids)})")
        
        time.sleep(RATE_LIMIT)
    
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for _id in all_ids:
        if _id not in seen:
            seen.add(_id)
            unique.append(_id)
    
    print(f"\nCollected {len(unique)} unique hacktivity IDs")
    return unique


def fetch_report(report_id):
    """Download a single report, return dict if it's a useful full-disclosure report."""
    cache_path = os.path.join(DATA_DIR, f"{report_id}.json")
    
    # Already cached
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            data = json.load(f)
        if data.get("visibility") == "full":
            vi = data.get("vulnerability_information", "") or ""
            if len(vi) > 200:
                return data
        return None
    
    url = REPORT_URL.format(report_id)
    data = make_request(url)
    
    if not data:
        return None
    
    if data.get("visibility") != "full":
        return None
    
    vi = data.get("vulnerability_information", "") or ""
    if len(vi) <= 200:
        return None
    
    # Save it
    with open(cache_path, "w") as f:
        json.dump(data, f, indent=2)
    
    return data


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Count existing valid reports
    existing = 0
    for fname in os.listdir(DATA_DIR):
        if fname.endswith(".json"):
            try:
                fpath = os.path.join(DATA_DIR, fname)
                with open(fpath) as f:
                    d = json.load(f)
                if d.get("visibility") == "full":
                    vi = d.get("vulnerability_information", "") or ""
                    if len(vi) > 200:
                        existing += 1
            except:
                pass
    
    print(f"Existing valid reports: {existing}")
    print(f"Target: {TARGET_REPORTS} total full-disclosure reports\n")
    
    # Phase 1: Get IDs
    print("Phase 1: Fetching report IDs from GraphQL...")
    ids = get_hacktivity_ids()
    
    if not ids:
        print("No IDs fetched, exiting.")
        sys.exit(1)
    
    # Phase 2: Fetch reports
    print(f"\nPhase 2: Fetching individual reports...")
    found = existing
    checked = 0
    new_found = 0
    errors = 0
    
    for rid in ids:
        if found >= TARGET_REPORTS:
            break
        
        checked += 1
        report = fetch_report(rid)
        
        if report:
            title = report.get("title", "Unknown")[:60]
            severity = report.get("severity_rating", "none")
            team = report.get("team", {}).get("handle", "?")
            found += 1
            new_found += 1
            print(f"  ✅ [{found}] {rid} | {severity} | {team} | {title}")
        else:
            errors += 1
        
        if checked % 25 == 0:
            print(f"  ... checked {checked}/{len(ids)}, found {found} total ({new_found} new)")
        
        time.sleep(RATE_LIMIT)
    
    # Final count
    total_files = len([f for f in os.listdir(DATA_DIR) if f.endswith(".json")])
    print(f"\n{'='*60}")
    print(f"Scrape complete!")
    print(f"  Checked: {checked} IDs")
    print(f"  New reports saved: {new_found}")
    print(f"  Total valid reports: {found}")
    print(f"  Total files in data/reports/: {total_files}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
