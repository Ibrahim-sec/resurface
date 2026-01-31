#!/usr/bin/env python3
"""
Resurface CLI — LLM-Powered Vulnerability Regression Hunter

Usage:
    python resurface.py scrape [--limit N]
    python resurface.py parse [--report ID | --all]
    python resurface.py replay --report ID --target URL
    python resurface.py replay-all --target URL [--limit N]
    python resurface.py report [--format html|json]
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
            headless=config.browser.headless,
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
    
    # Validate
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
    }
    
    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args, config)
    else:
        print(f"❌ Unknown command: {args.command}")
        arg_parser.print_help()


if __name__ == '__main__':
    main()
