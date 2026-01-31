"""
HackerOne Hacktivity scraper — collects disclosed reports
"""
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
from loguru import logger


class HackerOneScraper:
    """Scrapes disclosed reports from HackerOne's Hacktivity feed"""
    
    GRAPHQL_URL = "https://hackerone.com/graphql"
    REPORT_URL = "https://hackerone.com/reports/{report_id}.json"
    
    GRAPHQL_QUERY = """query {{
        search(
            index: CompleteHacktivityReportIndex,
            query_string: "{query}",
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
    
    def __init__(self, cache_dir: str = "data/reports", rate_limit: float = 0.35,
                 user_agent: str = "Resurface/1.0"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit = rate_limit
        self.headers = {
            'User-Agent': user_agent,
            'Content-Type': 'application/json'
        }
    
    def _request(self, url: str, data: dict = None) -> Optional[dict]:
        """Make an HTTP request and return JSON response"""
        try:
            req = urllib.request.Request(url, headers=self.headers)
            if data:
                req.data = json.dumps(data).encode()
            resp = urllib.request.urlopen(req, timeout=15)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            logger.warning(f"HTTP {e.code} for {url}")
            return None
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
    
    def get_hacktivity_ids(self, query: str = "*", max_pages: int = 20,
                           per_page: int = 50) -> list[str]:
        """Fetch report IDs from HackerOne's GraphQL Hacktivity index"""
        all_ids = []
        cursor = ""
        
        for page in range(max_pages):
            after_clause = f', after: "{cursor}"' if cursor else ''
            gql_query = self.GRAPHQL_QUERY.format(
                query=query, first=per_page, after_clause=after_clause
            )
            
            result = self._request(self.GRAPHQL_URL, {"query": gql_query})
            
            if not result or 'errors' in result:
                logger.warning(f"GraphQL error on page {page + 1}")
                break
            
            edges = result.get('data', {}).get('search', {}).get('edges', [])
            if not edges:
                break
            
            for edge in edges:
                _id = edge.get('node', {}).get('_id')
                if _id:
                    all_ids.append(_id)
            
            cursor = edges[-1].get('cursor', '')
            total = result.get('data', {}).get('search', {}).get('total_count', '?')
            logger.info(f"Page {page + 1}: fetched {len(edges)} IDs (total available: {total})")
            
            time.sleep(self.rate_limit)
        
        logger.info(f"Collected {len(all_ids)} hacktivity IDs")
        return all_ids
    
    def fetch_report(self, report_id: str | int) -> Optional[dict]:
        """Fetch a single report by ID, using cache if available"""
        cache_path = self.cache_dir / f"{report_id}.json"
        
        # Check cache first
        if cache_path.exists():
            with open(cache_path) as f:
                return json.load(f)
        
        # Fetch from API
        url = self.REPORT_URL.format(report_id=report_id)
        data = self._request(url)
        
        if data and data.get('visibility') == 'full':
            vi = data.get('vulnerability_information', '') or ''
            if len(vi) > 100:
                # Cache the full report
                with open(cache_path, 'w') as f:
                    json.dump(data, f, indent=2)
                return data
        
        return None
    
    def scrape(self, max_reports: int = 100, query: str = "*") -> list[dict]:
        """
        Main scrape method — fetches hacktivity IDs and downloads full reports.
        
        Returns list of full-disclosure reports with PoC content.
        """
        logger.info(f"Starting HackerOne scrape (target: {max_reports} reports)")
        
        # Phase 1: Get candidate IDs
        ids = self.get_hacktivity_ids(query=query, max_pages=max_reports // 2)
        
        # Phase 2: Fetch and filter reports
        full_reports = []
        
        for i, rid in enumerate(ids):
            if len(full_reports) >= max_reports:
                break
            
            report = self.fetch_report(rid)
            if report:
                title = report.get('title', 'Unknown')
                severity = report.get('severity_rating', 'none')
                team = report.get('team', {}).get('handle', '?')
                logger.info(f"✅ [{len(full_reports) + 1}] {rid} | {severity} | {team} | {title[:50]}")
                full_reports.append(report)
            
            if (i + 1) % 50 == 0:
                logger.info(f"Progress: checked {i + 1}/{len(ids)}, found {len(full_reports)} full reports")
            
            time.sleep(self.rate_limit)
        
        # Save index
        index = [{
            'id': r.get('id'),
            'title': r.get('title'),
            'severity': r.get('severity_rating'),
            'weakness': r.get('weakness', {}).get('name') if r.get('weakness') else None,
            'team': r.get('team', {}).get('handle'),
            'disclosed_at': r.get('disclosed_at')
        } for r in full_reports]
        
        index_path = self.cache_dir.parent / 'reports_index.json'
        with open(index_path, 'w') as f:
            json.dump(index, f, indent=2)
        
        logger.info(f"Scrape complete: {len(full_reports)} full-disclosure reports saved")
        return full_reports


def scrape_hackerone(max_reports: int = 100, cache_dir: str = "data/reports") -> list[dict]:
    """Convenience function to scrape HackerOne"""
    scraper = HackerOneScraper(cache_dir=cache_dir)
    return scraper.scrape(max_reports=max_reports)
