#!/usr/bin/env python3
"""
Resurface CLI — LLM-Powered Vulnerability Regression Hunter

Usage:
    python resurface.py scrape [--limit N]
    python resurface.py parse [--report ID | --all]
    python resurface.py replay --report ID --target URL [--browser]
    python resurface.py replay-all --target URL [--limit N] [--browser]
    python resurface.py stats
    python resurface.py export [--format html|json]
    python resurface.py list
"""
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import asdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.config import load_config
from src.scraper.hackerone import HackerOneScraper
from src.parser.llm_parser import LLMParser
from src.engine.http_replayer import HTTPReplayer
from src.validator.llm_validator import LLMValidator
from src.models import ReplayResult
from src.database import init_db, save_report, save_parsed, save_result, get_stats, get_all_results
from src.reporter.summary_report import generate_summary_report

try:
    from loguru import logger
except ImportError:
    import logging as logger


BANNER = """
╔══════════════════════════════════════════════════╗
║                                                  ║
║   🔄  R E S U R F A C E                         ║
║                                                  ║
║   LLM-Powered Vulnerability Regression Hunter    ║
║   Bugs don't die. They resurface.                ║
║                                                  ║
╚══════════════════════════════════════════════════╝
"""


def cmd_scrape(args, config):
    """Scrape disclosed reports from HackerOne"""
    print(f"🔍 Scraping HackerOne Hacktivity (limit: {args.limit})...")
    
    scraper = HackerOneScraper(
        cache_dir=config.scraper.cache_dir,
        rate_limit=1.0 / config.scraper.rate_limit
    )
    reports = scraper.scrape(max_reports=args.limit)
    
    print(f"\n✅ Scraped {len(reports)} fully-disclosed reports")
    print(f"📁 Saved to: {config.scraper.cache_dir}/")
    
    # Show summary
    for r in reports[:10]:
        severity = r.get('severity_rating', '?')
        title = r.get('title', 'Unknown')[:60]
        team = r.get('team', {}).get('handle', '?')
        print(f"  [{severity:8s}] {team:15s} | {title}")
    
    if len(reports) > 10:
        print(f"  ... and {len(reports) - 10} more")


def cmd_list(args, config):
    """List scraped reports"""
    reports_dir = Path(config.scraper.cache_dir)
    if not reports_dir.exists():
        print("❌ No reports directory found. Run 'scrape' first.")
        return
    
    report_files = sorted(reports_dir.glob("*.json"))
    if not report_files:
        print("❌ No reports found. Run 'scrape' first.")
        return
    
    print(f"📋 {len(report_files)} reports in {reports_dir}/\n")
    
    for f in report_files:
        try:
            with open(f) as fp:
                r = json.load(fp)
            rid = r.get('id', '?')
            severity = r.get('severity_rating', '?')
            title = r.get('title', 'Unknown')[:55]
            team = r.get('team', {}).get('handle', '?')
            weakness = r.get('weakness', {})
            weakness_name = (weakness.get('name', '') if weakness else '')[:25]
            print(f"  {rid:>8} | {severity:8s} | {team:15s} | {weakness_name:25s} | {title}")
        except:
            print(f"  ⚠️  Could not read {f.name}")


def cmd_parse(args, config):
    """Parse reports using LLM"""
    if not config.llm.api_key:
        print("❌ No LLM API key configured!")
        print("   Set GEMINI_API_KEY environment variable or configure in config.yaml")
        return
    
    parser = LLMParser(
        api_key=config.llm.api_key,
        model=config.llm.model,
        temperature=config.llm.temperature,
        provider=config.llm.provider
    )
    
    reports_dir = Path(config.scraper.cache_dir)
    parsed_dir = Path("data/parsed")
    parsed_dir.mkdir(parents=True, exist_ok=True)
    
    if args.report:
        # Parse single report
        report_file = reports_dir / f"{args.report}.json"
        if not report_file.exists():
            print(f"❌ Report {args.report} not found in {reports_dir}/")
            return
        
        with open(report_file) as f:
            report = json.load(f)
        
        print(f"🧠 Parsing report {args.report}...")
        result = parser.parse_report(report)
        
        if result:
            # Save parsed result
            output = asdict(result)
            output['parsed_at'] = output['parsed_at'].isoformat() if output['parsed_at'] else None
            
            with open(parsed_dir / f"{args.report}_parsed.json", 'w') as f:
                json.dump(output, f, indent=2)
            
            print(f"\n✅ Parsed successfully!")
            print(f"   Type: {result.vuln_type.value}")
            print(f"   Target: {result.target_url or 'Unknown'}")
            print(f"   Steps: {len(result.steps)}")
            print(f"   Method: {result.replay_method.value}")
            print(f"   Confidence: {result.confidence}")
            print(f"   Auth required: {result.requires_auth}")
            print(f"\n   Steps:")
            for step in result.steps:
                print(f"     {step.order}. {step.description[:70]}")
        else:
            print("❌ Failed to parse report")
    
    elif args.all:
        # Parse all reports
        report_files = sorted(reports_dir.glob("*.json"))
        print(f"🧠 Parsing {len(report_files)} reports...")
        
        reports = []
        for f in report_files:
            with open(f) as fp:
                reports.append(json.load(fp))
        
        results = parser.parse_batch(reports)
        
        for r in results:
            output = asdict(r)
            output['parsed_at'] = output['parsed_at'].isoformat() if output['parsed_at'] else None
            with open(parsed_dir / f"{r.report_id}_parsed.json", 'w') as f:
                json.dump(output, f, indent=2)
        
        print(f"\n✅ Parsed {len(results)}/{len(reports)} reports")


def cmd_replay(args, config):
    """Replay a parsed report against a target"""
    if not config.llm.api_key:
        print("❌ No LLM API key configured!")
        return
    
    parsed_dir = Path("data/parsed")
    parsed_file = parsed_dir / f"{args.report}_parsed.json"
    
    if not parsed_file.exists():
        print(f"❌ Parsed report {args.report} not found. Run 'parse --report {args.report}' first.")
        return
    
    with open(parsed_file) as f:
        parsed_data = json.load(f)
    
    # Reconstruct ParsedReport from dict
    from src.models import ParsedReport, PoC_Step, VulnType, ReplayMethod
    
    steps = [PoC_Step(**s) for s in parsed_data.get('steps', [])]
    parsed_report = ParsedReport(
        report_id=parsed_data['report_id'],
        title=parsed_data['title'],
        vuln_type=VulnType(parsed_data['vuln_type']),
        severity=parsed_data['severity'],
        target_url=parsed_data.get('target_url'),
        target_domain=parsed_data.get('target_domain'),
        weakness=parsed_data.get('weakness'),
        description=parsed_data.get('description', ''),
        impact=parsed_data.get('impact', ''),
        steps=steps,
        replay_method=ReplayMethod(parsed_data.get('replay_method', 'http')),
        requires_auth=parsed_data.get('requires_auth', False),
        auth_details=parsed_data.get('auth_details'),
        original_report_text=parsed_data.get('original_report_text', ''),
        confidence=parsed_data.get('confidence', 0.0)
    )
    
    print(f"🔄 Replaying report {args.report} against {args.target}...")
    print(f"   Vuln type: {parsed_report.vuln_type.value}")
    print(f"   Steps: {len(parsed_report.steps)}")
    print(f"   Method: {parsed_report.replay_method.value}")
    print()
    
    # Choose replay method
    use_browser = parsed_report.replay_method.value == 'browser' or args.browser
    
    if use_browser:
        from src.browser.browser_replayer import BrowserReplayer
        print("🌐 Using BROWSER replay engine (watch on noVNC!)")
        replayer = BrowserReplayer(
            api_key=config.llm.api_key,
            model=config.llm.model,
            headless=False if args.browser else config.browser.headless,
            screenshot=config.browser.screenshot,
            timeout=config.browser.timeout,
            provider=config.llm.provider
        )
    else:
        print("📡 Using HTTP replay engine")
        replayer = HTTPReplayer(
            timeout=config.engine.timeout,
            max_retries=config.engine.max_retries,
            follow_redirects=config.engine.follow_redirects
        )
    
    replay_result = replayer.replay(parsed_report, target_override=args.target)
    
    # If browser engine already confirmed vulnerability (e.g., caught alert dialog),
    # trust the direct detection over LLM validation
    if replay_result.result == ReplayResult.VULNERABLE and use_browser:
        print("🚨 Browser engine directly confirmed vulnerability (dialog/alert captured)!")
        replay_result.confidence = 0.95
        replay_result.llm_analysis = (
            "CONFIRMED BY BROWSER ENGINE: The vulnerability was directly detected during "
            "browser replay. An alert/dialog was triggered, confirming the XSS payload executed "
            "in the browser context. This is a definitive detection — no LLM analysis needed."
        )
    else:
        # Use LLM validation for HTTP-based replays or inconclusive browser results
        print("🧠 Validating results with LLM...")
        validator = LLMValidator(
            api_key=config.llm.api_key,
            model=config.llm.model,
            provider=config.llm.provider
        )
        replay_result = validator.validate(replay_result)
    
    # Save result
    results_dir = Path(config.reporter.output_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    
    result_data = {
        'report_id': replay_result.report_id,
        'title': parsed_report.title,
        'vuln_type': parsed_report.vuln_type.value,
        'target': args.target,
        'result': replay_result.result.value,
        'confidence': replay_result.confidence,
        'analysis': replay_result.llm_analysis,
        'duration_seconds': replay_result.duration_seconds,
        'replayed_at': replay_result.replayed_at.isoformat() if replay_result.replayed_at else None,
        'evidence_count': len(replay_result.evidence),
        'steps_executed': len(parsed_report.steps)
    }
    
    with open(results_dir / f"{args.report}_result.json", 'w') as f:
        json.dump(result_data, f, indent=2)
    
    # Display result
    result_emoji = {
        ReplayResult.VULNERABLE: "🔴 VULNERABLE — Bug has resurfaced!",
        ReplayResult.FIXED: "🟢 FIXED — Vulnerability appears patched",
        ReplayResult.PARTIAL: "🟡 PARTIAL — Fix incomplete, bypass may exist",
        ReplayResult.INCONCLUSIVE: "⚪ INCONCLUSIVE — Could not determine",
        ReplayResult.ERROR: "❌ ERROR — Replay failed",
    }
    
    print(f"\n{'='*60}")
    print(f"  RESULT: {result_emoji.get(replay_result.result, '?')}")
    print(f"  Confidence: {replay_result.confidence:.0%}")
    print(f"  Duration: {replay_result.duration_seconds:.1f}s")
    print(f"{'='*60}")
    print(f"\n📝 Analysis:\n{replay_result.llm_analysis}")
    print(f"\n💾 Result saved to: {results_dir}/{args.report}_result.json")


def cmd_replay_all(args, config):
    """Parse and replay ALL reports against a target"""
    if not config.llm.api_key:
        print("❌ No LLM API key configured!")
        return

    # Initialize database
    db_path = init_db()
    print(f"💾 Database: {db_path}")

    reports_dir = Path(config.scraper.cache_dir)
    parsed_dir = Path("data/parsed")
    results_dir = Path(config.reporter.output_dir)
    parsed_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    report_files = sorted(reports_dir.glob("*.json"))
    if not report_files:
        print(f"❌ No reports found in {reports_dir}/. Run 'scrape' first.")
        return

    if args.limit:
        report_files = report_files[:args.limit]

    print(f"🔄 Replay-all: {len(report_files)} reports → {args.target}")
    print(f"   Browser mode: {'ON' if args.browser else 'OFF'}")
    print()

    # Initialize components
    parser = LLMParser(
        api_key=config.llm.api_key,
        model=config.llm.model,
        temperature=config.llm.temperature,
        provider=config.llm.provider
    )
    validator = LLMValidator(
        api_key=config.llm.api_key,
        model=config.llm.model,
        provider=config.llm.provider
    )

    from src.models import ParsedReport, PoC_Step, VulnType, ReplayMethod

    counters = {"vulnerable": 0, "fixed": 0, "partial": 0, "inconclusive": 0, "error": 0}

    for idx, report_file in enumerate(report_files, 1):
        try:
            with open(report_file) as fp:
                report = json.load(fp)

            rid = report.get("id", "?")
            title = report.get("title", "Unknown")[:50]
            print(f"  [{idx}/{len(report_files)}] Report {rid}: {title}")

            # Save report to DB
            save_report(report, db_path)

            # Parse
            parsed_file = parsed_dir / f"{rid}_parsed.json"
            if parsed_file.exists():
                with open(parsed_file) as f:
                    parsed_data = json.load(f)
                print(f"       ✓ Already parsed, loading from cache")
            else:
                print(f"       🧠 Parsing with LLM...")
                parsed_result = parser.parse_report(report)
                if not parsed_result:
                    print(f"       ⚠️  Parse failed, skipping")
                    counters["error"] += 1
                    continue
                parsed_data = asdict(parsed_result)
                parsed_data['parsed_at'] = (parsed_data['parsed_at'].isoformat()
                                            if parsed_data.get('parsed_at') else None)
                with open(parsed_file, 'w') as f:
                    json.dump(parsed_data, f, indent=2)

            # Save parsed to DB
            save_parsed(parsed_data, db_path)

            # Reconstruct ParsedReport for replayer
            steps = [PoC_Step(**s) for s in parsed_data.get('steps', [])]
            parsed_report = ParsedReport(
                report_id=parsed_data['report_id'],
                title=parsed_data['title'],
                vuln_type=VulnType(parsed_data['vuln_type']),
                severity=parsed_data['severity'],
                target_url=parsed_data.get('target_url'),
                target_domain=parsed_data.get('target_domain'),
                weakness=parsed_data.get('weakness'),
                description=parsed_data.get('description', ''),
                impact=parsed_data.get('impact', ''),
                steps=steps,
                replay_method=ReplayMethod(parsed_data.get('replay_method', 'http')),
                requires_auth=parsed_data.get('requires_auth', False),
                auth_details=parsed_data.get('auth_details'),
                original_report_text=parsed_data.get('original_report_text', ''),
                confidence=parsed_data.get('confidence', 0.0)
            )

            # Replay
            use_browser = parsed_report.replay_method.value == 'browser' or args.browser
            if use_browser:
                from src.browser.browser_replayer import BrowserReplayer
                replayer = BrowserReplayer(
                    api_key=config.llm.api_key,
                    model=config.llm.model,
                    headless=config.browser.headless,
                    screenshot=config.browser.screenshot,
                    timeout=config.browser.timeout,
                    provider=config.llm.provider
                )
            else:
                replayer = HTTPReplayer(
                    timeout=config.engine.timeout,
                    max_retries=config.engine.max_retries,
                    follow_redirects=config.engine.follow_redirects
                )

            print(f"       🔄 Replaying against {args.target}...")
            replay_result = replayer.replay(parsed_report, target_override=args.target)

            # Validate
            replay_result = validator.validate(replay_result)

            # Save result to DB
            result_data = {
                'report_id': replay_result.report_id,
                'result': replay_result.result.value if hasattr(replay_result.result, 'value') else replay_result.result,
                'confidence': replay_result.confidence,
                'target_url': args.target,
                'llm_analysis': replay_result.llm_analysis,
                'evidence': [asdict(e) for e in replay_result.evidence] if replay_result.evidence else [],
                'duration_seconds': replay_result.duration_seconds,
                'replayed_at': replay_result.replayed_at.isoformat() if replay_result.replayed_at else None,
            }
            save_result(result_data, db_path)

            # Also save JSON file for compatibility
            file_result = dict(result_data)
            file_result['title'] = parsed_report.title
            file_result['vuln_type'] = parsed_report.vuln_type.value
            file_result['target'] = args.target
            file_result['analysis'] = replay_result.llm_analysis
            file_result['evidence_count'] = len(replay_result.evidence)
            file_result['steps_executed'] = len(parsed_report.steps)
            with open(results_dir / f"{rid}_result.json", 'w') as f:
                json.dump(file_result, f, indent=2)

            status = replay_result.result.value if hasattr(replay_result.result, 'value') else str(replay_result.result)
            counters[status] = counters.get(status, 0) + 1

            status_emoji = {"vulnerable": "🔴", "fixed": "🟢", "partial": "🟡",
                            "inconclusive": "⚪", "error": "❌"}
            print(f"       {status_emoji.get(status, '?')} {status.upper()} (conf: {replay_result.confidence:.0%})")

        except Exception as e:
            print(f"       ❌ Error: {e}")
            counters["error"] += 1

    # Summary
    print(f"\n{'='*60}")
    print(f"  REPLAY-ALL COMPLETE")
    print(f"{'='*60}")
    print(f"  🔴 Vulnerable: {counters['vulnerable']}")
    print(f"  🟢 Fixed:      {counters['fixed']}")
    print(f"  🟡 Partial:    {counters['partial']}")
    print(f"  ⚪ Inconclusive: {counters['inconclusive']}")
    print(f"  ❌ Errors:     {counters['error']}")
    print(f"  📊 Total:      {sum(counters.values())}")
    print(f"{'='*60}")


def cmd_stats(args, config):
    """Show database statistics"""
    db_path = init_db()
    stats = get_stats(db_path)

    print(f"📊 Resurface Statistics")
    print(f"{'='*50}")
    print(f"  Reports scraped:   {stats['total_reports']}")
    print(f"  Reports parsed:    {stats['parsed_count']}")
    print(f"  Total replays:     {stats['total_replays']}")
    print(f"  Avg duration:      {stats['avg_duration_seconds']:.1f}s")
    print()

    rb = stats.get("result_breakdown", {})
    if rb:
        print(f"  Result Breakdown:")
        emoji = {"vulnerable": "🔴", "fixed": "🟢", "partial": "🟡",
                 "inconclusive": "⚪", "error": "❌"}
        for status, count in sorted(rb.items(), key=lambda x: -x[1]):
            e = emoji.get(status, "?")
            avg_c = stats.get("avg_confidence", {}).get(status, 0)
            print(f"    {e} {status:15s} {count:4d}  (avg conf: {avg_c:.0%})")
    print()

    vtd = stats.get("vuln_type_distribution", {})
    if vtd:
        print(f"  Vulnerability Types:")
        for vt, count in sorted(vtd.items(), key=lambda x: -x[1]):
            print(f"    {vt:25s} {count:4d}")
    print()

    tt = stats.get("top_teams", {})
    if tt:
        print(f"  Top Programs:")
        for team, count in list(sorted(tt.items(), key=lambda x: -x[1]))[:10]:
            print(f"    {team:25s} {count:4d}")
    print()

    sd = stats.get("severity_distribution", {})
    if sd:
        print(f"  Severity Distribution:")
        sev_emoji = {"critical": "🔥", "high": "🔴", "medium": "🟠", "low": "🟢", "none": "⚪"}
        for sev, count in sorted(sd.items(), key=lambda x: -x[1]):
            e = sev_emoji.get(sev.lower(), "•")
            print(f"    {e} {sev:15s} {count:4d}")


def cmd_export(args, config):
    """Export all results to a single HTML summary report"""
    db_path = init_db()
    results = get_all_results(db_path)
    stats = get_stats(db_path)

    if not results:
        print("❌ No replay results found. Run 'replay' or 'replay-all' first.")
        return

    output_dir = Path(config.reporter.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    fmt = getattr(args, 'format', 'html') or 'html'

    if fmt == 'json':
        output_path = str(output_dir / "summary.json")
        with open(output_path, 'w') as f:
            json.dump({"stats": stats, "results": results}, f, indent=2, default=str)
        print(f"✅ JSON export saved to: {output_path}")
    else:
        output_path = str(output_dir / "summary.html")
        generate_summary_report(results, stats, output_path)
        print(f"✅ HTML summary report saved to: {output_path}")
        print(f"   📊 {stats['total_replays']} results across {stats['total_reports']} reports")


def main():
    print(BANNER)
    
    arg_parser = argparse.ArgumentParser(
        description="Resurface — LLM-Powered Vulnerability Regression Hunter"
    )
    arg_parser.add_argument('--config', '-c', default='configs/config.yaml',
                           help='Path to config file')
    
    subparsers = arg_parser.add_subparsers(dest='command', help='Commands')
    
    # Scrape command
    scrape_parser = subparsers.add_parser('scrape', help='Scrape disclosed reports')
    scrape_parser.add_argument('--limit', '-l', type=int, default=100,
                              help='Max reports to scrape')
    
    # List command
    subparsers.add_parser('list', help='List scraped reports')
    
    # Parse command
    parse_parser = subparsers.add_parser('parse', help='Parse reports with LLM')
    parse_group = parse_parser.add_mutually_exclusive_group(required=True)
    parse_group.add_argument('--report', '-r', help='Report ID to parse')
    parse_group.add_argument('--all', '-a', action='store_true', help='Parse all reports')
    
    # Replay command
    replay_parser = subparsers.add_parser('replay', help='Replay a parsed report')
    replay_parser.add_argument('--report', '-r', required=True, help='Report ID')
    replay_parser.add_argument('--target', '-t', required=True, help='Target URL')
    replay_parser.add_argument('--browser', '-b', action='store_true', 
                              help='Force browser-based replay (visible on noVNC)')

    # Replay-all command
    replay_all_parser = subparsers.add_parser('replay-all',
                                              help='Parse and replay ALL reports against a target')
    replay_all_parser.add_argument('--target', '-t', required=True, help='Target URL')
    replay_all_parser.add_argument('--limit', '-l', type=int, default=None,
                                   help='Max reports to process')
    replay_all_parser.add_argument('--browser', '-b', action='store_true',
                                   help='Force browser-based replay')

    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export results to summary report')
    export_parser.add_argument('--format', '-f', choices=['html', 'json'], default='html',
                               help='Output format (default: html)')

    args = arg_parser.parse_args()
    
    if not args.command:
        arg_parser.print_help()
        return
    
    # Load config
    config = load_config(args.config)
    
    # Dispatch
    commands = {
        'scrape': cmd_scrape,
        'list': cmd_list,
        'parse': cmd_parse,
        'replay': cmd_replay,
        'replay-all': cmd_replay_all,
        'stats': cmd_stats,
        'export': cmd_export,
    }
    
    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args, config)
    else:
        print(f"❌ Unknown command: {args.command}")
        arg_parser.print_help()


if __name__ == '__main__':
    main()
