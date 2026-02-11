#!/usr/bin/env python3
"""
Resurface CLI — LLM-Powered Vulnerability Regression Hunter

Usage:
    python resurface.py scrape [--limit N]
    python resurface.py parse [--report ID | --all]
    python resurface.py replay --report ID --target URL [--browser] [--blind] [--enrich] [--retries N]
    python resurface.py replay-all --target URL [--limit N] [--browser] [--blind]
    python resurface.py benchmark [--target URL] [--reports IDs...] [--modes http no-llm browser-use browser-use-blind]
    python resurface.py hunt --target URL [--vuln-types xss sqli idor] [--max-actions 30]
    python resurface.py stats
    python resurface.py export [--format html|json]
    python resurface.py list
"""
import os
import sys
import json
import asyncio
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import asdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.browser import DEFAULT_CHROME_ARGS
from src.config import load_config
from src.scraper.hackerone import HackerOneScraper
from src.parser.llm_parser import LLMParser
from src.engine.http_replayer import HTTPReplayer
from src.validator.llm_validator import LLMValidator
from src.models import ReplayResult
from src.database import init_db, save_report, save_parsed, save_result, get_stats, get_all_results
from src.reporter.summary_report import generate_summary_report
from src.notifications.notifier import Notifier

try:
    from src.auth.auth_manager import AuthManager
    from src.auth.auth_config import load_auth_config
    HAS_AUTH = True
except ImportError:
    HAS_AUTH = False

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


def _reconstruct_parsed_report(parsed_data: dict):
    """Reconstruct a ParsedReport from a dict (loaded from JSON)."""
    from src.models import ParsedReport, PoC_Step, VulnType, ReplayMethod
    steps = [PoC_Step(**s) for s in parsed_data.get('steps', [])]
    return ParsedReport(
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
        confidence=parsed_data.get('confidence', 0.0),
    )


def _get_auth_manager(config):
    """Create an AuthManager from config if auth profiles exist."""
    if not HAS_AUTH:
        return None
    try:
        auth_config = getattr(config, 'auth', None)
        if auth_config and hasattr(auth_config, 'profiles') and auth_config.profiles:
            manager = AuthManager(auth_config)
            profiles = auth_config.profiles
            # profiles can be dict or list
            if isinstance(profiles, dict):
                profile_list = profiles.values()
                count = len(profiles)
            else:
                profile_list = profiles
                count = len(profiles)
            print(f"🔐 Auth engine loaded: {count} profile(s)")
            for p in profile_list:
                print(f"   • {p.name} ({p.auth_type.value}) → {', '.join(p.domains)}")
            return manager
    except Exception as e:
        import traceback
        print(f"⚠️  Auth engine failed to load: {e}")
        traceback.print_exc()
    return None


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
    verbose = getattr(args, 'verbose', False)

    if not config.llm.api_key:
        print("❌ No LLM API key configured!")
        print("   Set GEMINI_API_KEY environment variable or configure in config.yaml")
        return
    
    parser = LLMParser(
        api_key=config.llm.api_key,
        model=config.llm.model,
        temperature=config.llm.temperature,
        provider=config.llm.provider,
        verbose=verbose,
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
    verbose = getattr(args, 'verbose', False)
    no_llm = getattr(args, 'no_llm', False)

    # Initialize cost tracker and deadline
    from src.cost_tracker import get_cost_tracker
    from src.deadline import Deadline
    cost_tracker = get_cost_tracker()
    cost_tracker.reset()
    max_time_seconds = getattr(args, 'max_time', None)
    if max_time_seconds is not None:
        max_time_seconds = max_time_seconds * 60  # convert minutes to seconds
    deadline = Deadline(max_seconds=max_time_seconds)
    max_cost = getattr(args, 'max_cost', None)
    max_turns = getattr(args, 'max_turns', None)
    num_attempts = getattr(args, 'attempts', 1) or 1

    if not no_llm and not config.llm.api_key:
        print("❌ No LLM API key configured!")
        return

    parsed_dir = Path("data/parsed")
    parsed_file = parsed_dir / f"{args.report}_parsed.json"

    if not parsed_file.exists():
        # In --no-llm mode, try parsing with regex on the fly
        if no_llm:
            reports_dir = Path(config.scraper.cache_dir)
            report_file = reports_dir / f"{args.report}.json"
            if report_file.exists():
                from src.parser.regex_parser import RegexParser
                print("🔧 No parsed file found — parsing with regex (--no-llm)...")
                regex_parser = RegexParser(verbose=verbose)
                with open(report_file) as f:
                    raw_report = json.load(f)
                parsed_result = regex_parser.parse_report(raw_report)
                if parsed_result:
                    parsed_dir.mkdir(parents=True, exist_ok=True)
                    from dataclasses import asdict
                    parsed_data = asdict(parsed_result)
                    parsed_data['parsed_at'] = (parsed_data['parsed_at'].isoformat()
                                                if parsed_data.get('parsed_at') else None)
                    with open(parsed_file, 'w') as f:
                        json.dump(parsed_data, f, indent=2)
                else:
                    print(f"❌ Regex parser also failed for report {args.report}")
                    return
            else:
                print(f"❌ Report {args.report} not found.")
                return
        else:
            print(f"❌ Parsed report {args.report} not found. Run 'parse --report {args.report}' first.")
            return
    
    with open(parsed_file) as f:
        parsed_data = json.load(f)
    
    parsed_report = _reconstruct_parsed_report(parsed_data)

    if no_llm:
        print(f"🔧 Replaying report {args.report} against {args.target} (NO-LLM BASELINE)...")
    else:
        print(f"🔄 Replaying report {args.report} against {args.target}...")
    print(f"   Vuln type: {parsed_report.vuln_type.value}")
    print(f"   Steps: {len(parsed_report.steps)}")
    print(f"   Method: {parsed_report.replay_method.value}")
    print()
    
    # Initialize auth manager
    auth_manager = _get_auth_manager(config) if not no_llm else None
    auto_auth_enabled = getattr(args, 'auto_auth', False)

    # Auto-auth: if enabled and report requires auth but no profile exists
    if auto_auth_enabled and not no_llm and auth_manager:
        from urllib.parse import urlparse
        target_domain = urlparse(args.target).netloc
        existing_profile = auth_manager.get_profile_for_domain(target_domain)
        if not existing_profile:
            print(f"🤖 Auto-auth: No auth profile for {target_domain}, starting autonomous auth...")
            auto_session = auth_manager.auto_authenticate(
                target_url=args.target,
                api_key=config.llm.api_key,
                model=config.llm.model,
                provider=config.llm.provider,
                headless=config.browser.headless,
                verbose=verbose,
            )
            if auto_session and auto_session.success:
                print(f"✅ Auto-auth: Session established ({len(auto_session.cookies)} cookies"
                      f"{', JWT token' if auto_session.authorization else ''})")
            else:
                print(f"⚠️  Auto-auth: Could not authenticate — continuing without auth")
        else:
            print(f"🔑 Using manual auth profile: {existing_profile.name}")
    elif auto_auth_enabled and not no_llm and not auth_manager:
        # Create a minimal auth manager for auto-auth
        from src.auth.auth_config import AuthConfig as _AC
        auth_manager = AuthManager(_AC())
        from urllib.parse import urlparse
        target_domain = urlparse(args.target).netloc
        print(f"🤖 Auto-auth: Starting autonomous auth for {target_domain}...")
        auto_session = auth_manager.auto_authenticate(
            target_url=args.target,
            api_key=config.llm.api_key,
            model=config.llm.model,
            provider=config.llm.provider,
            headless=config.browser.headless,
            verbose=verbose,
        )
        if auto_session and auto_session.success:
            print(f"✅ Auto-auth: Session established ({len(auto_session.cookies)} cookies"
                  f"{', JWT token' if auto_session.authorization else ''})")
        else:
            print(f"⚠️  Auto-auth: Could not authenticate — continuing without auth")

    # Choose replay method
    use_browser = parsed_report.replay_method.value == 'browser' or args.browser
    
    if use_browser:
        from src.browser.browseruse_replayer import BrowserUseReplayer
        blind_mode = getattr(args, 'blind', False)
        if blind_mode:
            print("🙈 Using Browser-Use agent in BLIND MODE (DOM-indexed, no URLs/steps)")
        else:
            print("🌐 Using Browser-Use agent (DOM-indexed browser automation)")
        # Determine provider and API keys
        groq_key = os.environ.get('GROQ_API_KEY', config.llm.api_key if config.llm.provider == 'groq' else None)
        gemini_key = os.environ.get('GEMINI_API_KEY', '')
        claude_key = os.environ.get('CLAUDE_API_KEY', '')
        if not claude_key:
            import yaml
            try:
                with open(os.path.join(config.base_dir, 'configs', 'config.yaml')) as _f:
                    _raw = yaml.safe_load(_f) or {}
                    claude_key = _raw.get('vision', {}).get('claude_api_key', '')
            except:
                pass
        # Provider priority: claude (best) > gemini (free) > groq (free but 500K TPD)
        if claude_key:
            bu_provider = 'claude'
            bu_model = 'claude-sonnet-4-0'
        elif gemini_key:
            bu_provider = 'gemini'
            bu_model = 'gemini-2.0-flash'
        elif groq_key:
            bu_provider = 'claude'
            bu_model = 'claude-sonnet-4-0'
        else:
            print("❌ No API key available for Browser-Use (need GEMINI_API_KEY, GROQ_API_KEY, or CLAUDE_API_KEY)")
            return
        print(f"   Provider: {bu_provider} ({bu_model})")
        use_cloud = getattr(args, 'cloud', False)
        if use_cloud:
            print("   ☁️  Cloud browser (remote)")
        replayer = BrowserUseReplayer(
            api_key=gemini_key or groq_key or claude_key,
            model=bu_model,
            provider=bu_provider,
            headless=False if args.browser else config.browser.headless,
            auth_manager=auth_manager,
            verbose=verbose,
            evidence_dir=config.reporter.output_dir,
            blind=blind_mode,
            groq_api_key=groq_key,
            claude_api_key=claude_key,
            use_cloud=use_cloud,
        )
    else:
        print("📡 Using HTTP replay engine")
        replayer = HTTPReplayer(
            timeout=config.engine.timeout,
            max_retries=config.engine.max_retries,
            follow_redirects=config.engine.follow_redirects,
            verbose=verbose,
            enable_mutation=not no_llm,
            auth_manager=auth_manager,
        )
    
    # ── Recon Phase (if --recon flag) ─────────────────────────────
    if getattr(args, 'recon', False) and use_browser and not no_llm:
        _run_recon_if_needed(args.target, config, verbose=verbose)

    # ── Enrichment + Retry Loop ────────────────────────────────────
    enrich_mode = getattr(args, 'enrich', False) and not no_llm
    max_retries = getattr(args, 'retries', 1)
    enriched_report = None

    if enrich_mode and use_browser:
        groq_enrich_key = os.environ.get('GROQ_API_KEY', config.llm.api_key if config.llm.provider == 'groq' else None)
        if groq_enrich_key:
            from src.enricher.report_enricher import ReportEnricher
            enricher = ReportEnricher(
                api_key=groq_enrich_key,
                verbose=verbose,
            )
            enriched_report = enricher.enrich(parsed_report, args.target)
            if enriched_report.enriched_prompt:
                print(f"   🧪 Enriched: {len(enriched_report.strategies)} strategies, "
                      f"{len(enriched_report.payload_variants)} payloads")
                if enriched_report.preflight and not enriched_report.preflight.target_alive:
                    print(f"   ⚠️  Preflight: target unreachable — {enriched_report.preflight.notes}")
                # Pass enriched prompt to replayer
                replayer._enriched_prompt = enriched_report.enriched_prompt
            else:
                print("   🧪 Enrichment failed — using default prompt")
        else:
            print("   🧪 Enrichment skipped (no Groq API key for cheap LLM calls)")

    # ── Multi-Attempt Loop ─────────────────────────────────────────
    results_dir = Path(config.reporter.output_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    resume_context = None
    replay_result = None

    for attempt in range(1, num_attempts + 1):
        # Check deadline before each attempt
        if deadline.expired:
            print(f"\n   ⏰ Time limit reached ({getattr(args, 'max_time', '?')} min) — aborting")
            break

        # Check cost limit before each attempt (after first)
        if attempt > 1 and max_cost is not None:
            current_cost = cost_tracker.get_summary()['estimated_cost_usd']
            if current_cost >= max_cost:
                print(f"\n   💰 Cost limit reached (${current_cost:.4f} >= ${max_cost:.4f}) — aborting")
                break

        if num_attempts > 1:
            print(f"\n   🔁 Attempt {attempt}/{num_attempts}" +
                  (f" (resume from previous)" if resume_context else ""))

        # Determine max_actions for this replay
        replay_max_actions = max_turns  # may be None (use replayer default)

        # Run replay with optional resume context
        if use_browser:
            replay_result = replayer.replay(
                parsed_report, target_override=args.target,
                max_actions=replay_max_actions,
                resume_context=resume_context,
            )
        else:
            replay_result = replayer.replay(parsed_report, target_override=args.target)

        # ── Post-failure retry with enrichment refinement ────────────
        if (enrich_mode and enriched_report and max_retries > 1
                and replay_result.result != ReplayResult.VULNERABLE
                and use_browser):
            from src.enricher.report_enricher import ReportEnricher
            groq_enrich_key = os.environ.get('GROQ_API_KEY', config.llm.api_key if config.llm.provider == 'groq' else None)
            if groq_enrich_key:
                enricher = ReportEnricher(api_key=groq_enrich_key, verbose=verbose)
                for retry in range(2, max_retries + 1):
                    # Check limits before each retry
                    if deadline.expired:
                        print(f"\n   ⏰ Time limit reached — stopping retries")
                        break
                    if max_cost is not None and cost_tracker.get_summary()['estimated_cost_usd'] >= max_cost:
                        print(f"\n   💰 Cost limit reached — stopping retries")
                        break
                    print(f"\n   🔄 Retry {retry}/{max_retries} — refining attack plan...")
                    # Build failure log from evidence
                    failure_log = f"Result: {getattr(replay_result.result, 'value', replay_result.result)}\n"
                    failure_log += f"Analysis: {replay_result.llm_analysis or 'N/A'}\n"
                    for ev in replay_result.evidence[:10]:
                        failure_log += f"  Step {ev.step_number}: {ev.notes[:200]}\n"
                    # Refine
                    enriched_report = enricher.refine(enriched_report, failure_log, args.target)
                    if enriched_report.enriched_prompt:
                        replayer._enriched_prompt = enriched_report.enriched_prompt
                    # Retry
                    replay_result = replayer.replay(parsed_report, target_override=args.target)
                    if replay_result.result == ReplayResult.VULNERABLE:
                        print(f"   ✅ Succeeded on retry {retry}!")
                        break

        # Save per-attempt result if multi-attempt
        if num_attempts > 1:
            attempt_result_data = {
                'report_id': replay_result.report_id,
                'attempt': attempt,
                'result': getattr(replay_result.result, 'value', replay_result.result),
                'confidence': replay_result.confidence,
                'analysis': replay_result.llm_analysis,
                'duration_seconds': replay_result.duration_seconds,
                'evidence_count': len(replay_result.evidence),
            }
            attempt_file = results_dir / f"{args.report}_attempt_{attempt}_result.json"
            with open(attempt_file, 'w') as f:
                json.dump(attempt_result_data, f, indent=2)

        # If VULNERABLE found, stop attempts
        if replay_result.result == ReplayResult.VULNERABLE:
            if num_attempts > 1:
                print(f"   ✅ VULNERABLE found on attempt {attempt}!")
            break

        # Build resume context for next attempt from this failed attempt
        if attempt < num_attempts:
            summary_lines = []
            summary_lines.append(f"## Attempt {attempt} Summary")
            summary_lines.append(f"Result: {getattr(replay_result.result, 'value', replay_result.result)}")
            summary_lines.append(f"Confidence: {replay_result.confidence:.0%}")
            summary_lines.append(f"Analysis: {replay_result.llm_analysis or 'N/A'}")
            summary_lines.append("")
            summary_lines.append("### Steps taken:")
            for ev in replay_result.evidence[:15]:
                summary_lines.append(f"- Step {ev.step_number}: {ev.notes[:300]}")
            summary_lines.append("")
            summary_lines.append("### What to try differently:")
            summary_lines.append("- Use different payloads or approaches")
            summary_lines.append("- Try different entry points or pages")
            summary_lines.append("- If blocked, try bypass techniques")
            resume_context = "\n".join(summary_lines)

            # Save the progress summary markdown
            summary_path = results_dir / f"{args.report}_attempt_{attempt}.md"
            with open(summary_path, 'w') as f:
                f.write(resume_context)
            print(f"   📝 Attempt {attempt} summary saved: {summary_path}")

    # If no replay_result was produced (e.g., deadline expired before first attempt)
    if replay_result is None:
        print("❌ No replay attempt was executed (time/cost limit reached)")
        return

    # If browser engine already confirmed vulnerability (e.g., caught alert dialog),
    # trust the direct detection over LLM validation
    if replay_result.result == ReplayResult.VULNERABLE and use_browser and not no_llm:
        # Check what kind of detection occurred
        evidence_texts = " ".join(
            (e.response_received or '') + ' ' + (e.notes or '')
            for e in replay_result.evidence
        ).lower()
        has_auth_bypass = 'auth_success' in evidence_texts or 'auth bypass' in evidence_texts
        has_network = 'network_intercept' in evidence_texts
        has_dialog = any('dialog' in (e.notes or '').lower() for e in replay_result.evidence)

        if has_auth_bypass or has_network:
            print("🔓 Browser engine confirmed vulnerability (auth bypass via network intercept)!")
            replay_result.confidence = 0.95
            replay_result.llm_analysis = (
                "CONFIRMED BY BROWSER ENGINE: SQL injection authentication bypass detected. "
                "The login endpoint returned a valid authentication token when the SQLi payload "
                "was submitted, confirming the vulnerability is exploitable."
            )
        elif has_dialog:
            print("🚨 Browser engine confirmed vulnerability (dialog/alert captured)!")
            replay_result.confidence = 0.95
            replay_result.llm_analysis = (
                "CONFIRMED BY BROWSER ENGINE: The vulnerability was directly detected during "
                "browser replay. An alert/dialog was triggered, confirming the XSS payload "
                "executed in the browser context. This is a definitive detection."
            )
        else:
            print("🔴 Browser agent confirmed vulnerability!")
            replay_result.confidence = 0.90
            replay_result.llm_analysis = (
                "CONFIRMED BY BROWSER AGENT: The browser-use agent detected indicators "
                "of successful exploitation during the replay."
            )
    elif no_llm:
        # Use heuristic validation in no-llm mode
        from src.validator.regex_validator import RegexValidator
        print("🔧 Validating results with heuristics (--no-llm)...")
        validator = RegexValidator(verbose=verbose)
        replay_result = validator.validate(replay_result)
    else:
        # Use LLM validation for HTTP-based replays or inconclusive browser results
        print("🧠 Validating results with LLM...")
        validator = LLMValidator(
            api_key=config.llm.api_key,
            model=config.llm.model,
            provider=config.llm.provider,
            verbose=verbose,
        )
        replay_result = validator.validate(replay_result)
    
    # ── Cost Summary ─────────────────────────────────────────────
    cost_summary = cost_tracker.get_summary()
    replay_result.cost_usd = cost_summary['estimated_cost_usd']
    replay_result.total_tokens = cost_summary['total_input_tokens'] + cost_summary['total_output_tokens']
    replay_result.llm_calls = cost_summary['call_count']

    # Save result
    result_data = {
        'report_id': replay_result.report_id,
        'title': parsed_report.title,
        'vuln_type': parsed_report.vuln_type.value,
        'target': args.target,
        'result': getattr(replay_result.result, 'value', replay_result.result),
        'confidence': replay_result.confidence,
        'analysis': replay_result.llm_analysis,
        'duration_seconds': replay_result.duration_seconds,
        'replayed_at': replay_result.replayed_at.isoformat() if replay_result.replayed_at else None,
        'evidence_count': len(replay_result.evidence),
        'steps_executed': len(parsed_report.steps),
        'cost_usd': cost_summary['estimated_cost_usd'],
        'total_tokens': cost_summary['total_input_tokens'] + cost_summary['total_output_tokens'],
        'llm_calls': cost_summary['call_count'],
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
    print(f"  {cost_tracker.format_summary()}")
    print(f"{'='*60}")
    print(f"\n📝 Analysis:\n{replay_result.llm_analysis}")
    print(f"\n💾 Result saved to: {results_dir}/{args.report}_result.json")

    if no_llm:
        print(f"\n  ⚠️  NO-LLM BASELINE MODE")
        print(f"  This result used regex-only parsing and heuristic validation.")
        print(f"  Compare with LLM-powered results for accuracy comparison.")

    # Notify if enabled
    if getattr(args, 'notify', False) or config.notifications.enabled:
        notifier = Notifier(config.notifications)
        notifier.notify(
            report_id=replay_result.report_id,
            title=parsed_report.title,
            vuln_type=parsed_report.vuln_type.value,
            severity=parsed_report.severity,
            confidence=replay_result.confidence,
            target_url=args.target,
            result=getattr(replay_result.result, 'value', replay_result.result),
            analysis=replay_result.llm_analysis or '',
        )


def cmd_replay_all(args, config):
    """Parse and replay ALL reports against a target"""
    no_llm = getattr(args, 'no_llm', False)

    if not no_llm and not config.llm.api_key:
        print("❌ No LLM API key configured!")
        return

    use_async = getattr(args, 'async_mode', False)

    if use_async:
        return _cmd_replay_all_async(args, config)
    else:
        return _cmd_replay_all_sync(args, config)


def _cmd_replay_all_sync(args, config):
    """Synchronous replay-all (original behavior)."""
    verbose = getattr(args, 'verbose', False)
    no_llm = getattr(args, 'no_llm', False)

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

    mode_label = "NO-LLM BASELINE" if no_llm else "LLM-powered"
    print(f"🔄 Replay-all: {len(report_files)} reports → {args.target}")
    print(f"   Browser mode: {'ON (browser-use)' if args.browser else 'OFF'}")
    print(f"   Mode: synchronous ({mode_label})")
    if verbose:
        print(f"   Verbose: ON")
    print()

    # Initialize components based on mode
    if no_llm:
        from src.parser.regex_parser import RegexParser
        from src.validator.regex_validator import RegexValidator
        parser = RegexParser(verbose=verbose)
        validator = RegexValidator(verbose=verbose)
    else:
        parser = LLMParser(
            api_key=config.llm.api_key,
            model=config.llm.model,
            temperature=config.llm.temperature,
            provider=config.llm.provider,
            verbose=verbose,
        )
        validator = LLMValidator(
            api_key=config.llm.api_key,
            model=config.llm.model,
            provider=config.llm.provider,
            verbose=verbose,
        )

    # Notifier
    notify = getattr(args, 'notify', False) or config.notifications.enabled
    notifier = Notifier(config.notifications) if notify else None

    # Auth manager
    auth_manager = _get_auth_manager(config) if not no_llm else None
    auto_auth_enabled = getattr(args, 'auto_auth', False)

    # Auto-auth: pre-authenticate before replaying reports
    if auto_auth_enabled and not no_llm:
        from urllib.parse import urlparse
        target_domain = urlparse(args.target).netloc

        if not auth_manager:
            from src.auth.auth_config import AuthConfig as _AC
            auth_manager = AuthManager(_AC())

        existing_profile = auth_manager.get_profile_for_domain(target_domain)
        if not existing_profile:
            print(f"🤖 Auto-auth: No auth profile for {target_domain}, starting autonomous auth...")
            auto_session = auth_manager.auto_authenticate(
                target_url=args.target,
                api_key=config.llm.api_key,
                model=config.llm.model,
                provider=config.llm.provider,
                headless=config.browser.headless,
                verbose=verbose,
            )
            if auto_session and auto_session.success:
                print(f"✅ Auto-auth: Session established ({len(auto_session.cookies)} cookies"
                      f"{', JWT token' if auto_session.authorization else ''})")
            else:
                print(f"⚠️  Auto-auth: Could not authenticate — continuing without auth")
        else:
            print(f"🔑 Using manual auth profile: {existing_profile.name}")
    print()

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
            if parsed_file.exists() and not no_llm:
                with open(parsed_file) as f:
                    parsed_data = json.load(f)
                print(f"       ✓ Already parsed, loading from cache")
            else:
                if no_llm:
                    print(f"       🔧 Parsing with regex (--no-llm)...")
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
                if not no_llm:
                    # Only cache LLM-parsed results (don't overwrite with regex results)
                    with open(parsed_file, 'w') as f:
                        json.dump(parsed_data, f, indent=2)

            # Save parsed to DB
            save_parsed(parsed_data, db_path)

            # Reconstruct ParsedReport
            parsed_report = _reconstruct_parsed_report(parsed_data)

            # Replay
            use_browser = parsed_report.replay_method.value == 'browser' or args.browser
            if use_browser:
                from src.browser.browseruse_replayer import BrowserUseReplayer
                groq_key = os.environ.get('GROQ_API_KEY', config.llm.api_key if config.llm.provider == 'groq' else None)
                gemini_key = os.environ.get('GEMINI_API_KEY', '')
                claude_key = os.environ.get('CLAUDE_API_KEY', '')
                if not claude_key:
                    import yaml as _yaml
                    try:
                        with open(os.path.join(config.base_dir, 'configs', 'config.yaml')) as _f:
                            _raw = _yaml.safe_load(_f) or {}
                            claude_key = _raw.get('vision', {}).get('claude_api_key', '')
                    except:
                        pass
                if claude_key:
                    bu_provider = 'claude'
                    bu_model = 'claude-sonnet-4-0'
                elif gemini_key:
                    bu_provider = 'gemini'
                    bu_model = 'gemini-2.0-flash'
                elif groq_key:
                    bu_provider = 'claude'
                    bu_model = 'claude-sonnet-4-0'
                else:
                    print("       ❌ No API key for browser-use, falling back to HTTP")
                    bu_provider = None
                if bu_provider:
                    replayer = BrowserUseReplayer(
                        api_key=gemini_key or groq_key or claude_key,
                        model=bu_model,
                        provider=bu_provider,
                        headless=config.browser.headless,
                        auth_manager=auth_manager,
                        verbose=verbose,
                        evidence_dir=config.reporter.output_dir,
                        blind=getattr(args, 'blind', False),
                        groq_api_key=groq_key,
                        claude_api_key=claude_key,
                    )
                else:
                    replayer = HTTPReplayer(
                        timeout=config.engine.timeout,
                        max_retries=config.engine.max_retries,
                        follow_redirects=config.engine.follow_redirects,
                        verbose=verbose,
                        enable_mutation=not no_llm,
                        auth_manager=auth_manager,
                    )
            else:
                replayer = HTTPReplayer(
                    timeout=config.engine.timeout,
                    max_retries=config.engine.max_retries,
                    follow_redirects=config.engine.follow_redirects,
                    verbose=verbose,
                    enable_mutation=not no_llm,
                    auth_manager=auth_manager,
                )

            print(f"       🔄 Replaying against {args.target}...")
            replay_result = replayer.replay(parsed_report, target_override=args.target)

            # Validate
            replay_result = validator.validate(replay_result)

            # Save result to DB
            result_data = {
                'report_id': replay_result.report_id,
                'result': getattr(replay_result.result, 'value', replay_result.result) if hasattr(replay_result.result, 'value') else replay_result.result,
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

            status = getattr(replay_result.result, 'value', replay_result.result) if hasattr(replay_result.result, 'value') else str(replay_result.result)
            counters[status] = counters.get(status, 0) + 1

            status_emoji = {"vulnerable": "🔴", "fixed": "🟢", "partial": "🟡",
                            "inconclusive": "⚪", "error": "❌"}
            print(f"       {status_emoji.get(status, '?')} {status.upper()} (conf: {replay_result.confidence:.0%})")

            # Notification
            if notifier:
                notifier.notify(
                    report_id=replay_result.report_id,
                    title=parsed_report.title,
                    vuln_type=parsed_report.vuln_type.value,
                    severity=parsed_report.severity,
                    confidence=replay_result.confidence,
                    target_url=args.target,
                    result=status,
                    analysis=replay_result.llm_analysis or '',
                )

        except Exception as e:
            print(f"       ❌ Error: {e}")
            counters["error"] += 1

    # Summary
    _print_summary(counters, no_llm=no_llm)


def _cmd_replay_all_async(args, config):
    """Async/parallel replay-all using asyncio + httpx."""
    import time as _time

    verbose = getattr(args, 'verbose', False)
    no_llm = getattr(args, 'no_llm', False)

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

    concurrency = getattr(args, 'concurrency', 5) or 5
    notify = getattr(args, 'notify', False) or config.notifications.enabled
    notifier = Notifier(config.notifications) if notify else None

    mode_label = "NO-LLM BASELINE" if no_llm else "LLM-powered"
    print(f"⚡ Async Replay-all: {len(report_files)} reports → {args.target}")
    print(f"   Concurrency: {concurrency}")
    print(f"   Mode: {mode_label}")
    print(f"   Notifications: {'ON' if notify else 'OFF'}")
    if verbose:
        print(f"   Verbose: ON")
    print()

    # Step 1: Parse all reports first (sync — LLM calls are sequential)
    if no_llm:
        from src.parser.regex_parser import RegexParser
        parser = RegexParser(verbose=verbose)
    else:
        parser = LLMParser(
            api_key=config.llm.api_key,
            model=config.llm.model,
            temperature=config.llm.temperature,
            provider=config.llm.provider,
            verbose=verbose,
        )

    parsed_reports = []
    for idx, report_file in enumerate(report_files, 1):
        try:
            with open(report_file) as fp:
                report = json.load(fp)

            rid = report.get("id", "?")
            title = report.get("title", "Unknown")[:50]
            save_report(report, db_path)

            parsed_file = parsed_dir / f"{rid}_parsed.json"
            if parsed_file.exists() and not no_llm:
                with open(parsed_file) as f:
                    parsed_data = json.load(f)
                print(f"  [{idx}/{len(report_files)}] Report {rid}: {title} ✓ cached")
            else:
                parse_label = "🔧 regex..." if no_llm else "🧠 parsing..."
                print(f"  [{idx}/{len(report_files)}] Report {rid}: {title} {parse_label}")
                parsed_result = parser.parse_report(report)
                if not parsed_result:
                    print(f"       ⚠️  Parse failed, skipping")
                    continue
                parsed_data = asdict(parsed_result)
                parsed_data['parsed_at'] = (parsed_data['parsed_at'].isoformat()
                                            if parsed_data.get('parsed_at') else None)
                if not no_llm:
                    with open(parsed_file, 'w') as f:
                        json.dump(parsed_data, f, indent=2)

            save_parsed(parsed_data, db_path)
            parsed_report = _reconstruct_parsed_report(parsed_data)
            parsed_reports.append(parsed_report)

        except Exception as e:
            print(f"  [{idx}/{len(report_files)}] ❌ Error loading report: {e}")

    if not parsed_reports:
        print("❌ No reports parsed successfully.")
        return

    print(f"\n⚡ Launching async replay of {len(parsed_reports)} reports "
          f"(concurrency={concurrency})...\n")

    # Step 2: Async replay
    from src.engine.async_replayer import AsyncHTTPReplayer

    async_replayer = AsyncHTTPReplayer(
        timeout=config.engine.timeout,
        max_retries=config.engine.max_retries,
        follow_redirects=config.engine.follow_redirects,
        concurrency=concurrency,
    )

    start = _time.time()
    replay_results = asyncio.run(
        async_replayer.replay_batch(parsed_reports, target_override=args.target)
    )
    replay_elapsed = _time.time() - start

    print(f"\n⏱️  Replay phase completed in {replay_elapsed:.1f}s")

    # Step 3: Validate all results (sequential)
    if no_llm:
        from src.validator.regex_validator import RegexValidator
        print(f"\n🔧 Validating {len(replay_results)} results with heuristics (--no-llm)...")
        validator = RegexValidator(verbose=verbose)
    else:
        print(f"\n🧠 Validating {len(replay_results)} results with LLM...")
        validator = LLMValidator(
            api_key=config.llm.api_key,
            model=config.llm.model,
            provider=config.llm.provider,
            verbose=verbose,
        )

    counters = {"vulnerable": 0, "fixed": 0, "partial": 0, "inconclusive": 0, "error": 0}

    for replay_result in replay_results:
        try:
            parsed_report = replay_result.parsed_report
            replay_result = validator.validate(replay_result)

            # Save to DB
            result_data = {
                'report_id': replay_result.report_id,
                'result': getattr(replay_result.result, 'value', replay_result.result) if hasattr(replay_result.result, 'value') else replay_result.result,
                'confidence': replay_result.confidence,
                'target_url': args.target,
                'llm_analysis': replay_result.llm_analysis,
                'evidence': [asdict(e) for e in replay_result.evidence] if replay_result.evidence else [],
                'duration_seconds': replay_result.duration_seconds,
                'replayed_at': replay_result.replayed_at.isoformat() if replay_result.replayed_at else None,
            }
            save_result(result_data, db_path)

            # Save JSON file
            file_result = dict(result_data)
            file_result['title'] = parsed_report.title
            file_result['vuln_type'] = parsed_report.vuln_type.value
            file_result['target'] = args.target
            file_result['analysis'] = replay_result.llm_analysis
            file_result['evidence_count'] = len(replay_result.evidence)
            file_result['steps_executed'] = len(parsed_report.steps)
            with open(results_dir / f"{replay_result.report_id}_result.json", 'w') as f:
                json.dump(file_result, f, indent=2)

            status = getattr(replay_result.result, 'value', replay_result.result) if hasattr(replay_result.result, 'value') else str(replay_result.result)
            counters[status] = counters.get(status, 0) + 1

            status_emoji = {"vulnerable": "🔴", "fixed": "🟢", "partial": "🟡",
                            "inconclusive": "⚪", "error": "❌"}
            print(f"  {status_emoji.get(status, '?')} #{replay_result.report_id}: "
                  f"{parsed_report.title[:45]} → {status.upper()} ({replay_result.confidence:.0%})")

            # Notification
            if notifier:
                notifier.notify(
                    report_id=replay_result.report_id,
                    title=parsed_report.title,
                    vuln_type=parsed_report.vuln_type.value,
                    severity=parsed_report.severity,
                    confidence=replay_result.confidence,
                    target_url=args.target,
                    result=status,
                    analysis=replay_result.llm_analysis or '',
                )

        except Exception as e:
            print(f"  ❌ Error validating #{replay_result.report_id}: {e}")
            counters["error"] += 1

    # Summary
    _print_summary(counters, no_llm=no_llm)


def _print_summary(counters: dict, no_llm: bool = False):
    """Print final summary counters."""
    print(f"\n{'='*60}")
    print(f"  REPLAY-ALL COMPLETE")
    print(f"{'='*60}")
    print(f"  🔴 Vulnerable:   {counters.get('vulnerable', 0)}")
    print(f"  🟢 Fixed:        {counters.get('fixed', 0)}")
    print(f"  🟡 Partial:      {counters.get('partial', 0)}")
    print(f"  ⚪ Inconclusive: {counters.get('inconclusive', 0)}")
    print(f"  ❌ Errors:       {counters.get('error', 0)}")
    print(f"  📊 Total:        {sum(counters.values())}")
    print(f"{'='*60}")

    if no_llm:
        print()
        print(f"  ⚠️  NO-LLM BASELINE MODE")
        print(f"  Results above used regex-only parsing and heuristic validation.")
        print(f"  Compare with LLM-powered results for accuracy comparison.")
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


def cmd_difficulty(args, config):
    """Score report difficulty for automated replay."""
    from src.utils.difficulty import score_report_difficulty, score_all_reports
    
    base = Path(getattr(config, 'base_dir', '')) or Path(__file__).parent
    
    if args.report:
        report_path = base / 'data' / 'reports' / f"{args.report}.json"
        parsed_path = base / 'data' / 'parsed' / f"{args.report}_parsed.json"
        result = score_report_difficulty(str(report_path), str(parsed_path))
        
        emoji = {'easy': '🟢', 'medium': '🟡', 'hard': '🔴'}[result['difficulty']]
        print(f"\n  Report {args.report}: {emoji} {result['difficulty'].upper()} (score: {result['score']}/100)")
        print(f"  Factors:")
        for k, v in result['factors'].items():
            icon = '✅' if v and v is not True or (isinstance(v, bool) and v) else '❌'
            if isinstance(v, bool):
                icon = '✅' if v else '❌'
            elif isinstance(v, int):
                icon = f"  {v}"
            print(f"    {icon} {k}: {v}")
    else:
        results = score_all_reports(str(base / 'data'))
        
        print(f"\n  {'Report':<10} {'Title':<45} {'Diff':<8} {'Score':>5}")
        print(f"  {'-'*10} {'-'*45} {'-'*8} {'-'*5}")
        for r in results:
            emoji = {'easy': '🟢', 'medium': '🟡', 'hard': '🔴'}[r['difficulty']]
            print(f"  {r['report_id']:<10} {r['title']:<45} {emoji} {r['difficulty']:<6} {r['score']:>4}")
        
        # Summary
        easy = sum(1 for r in results if r['difficulty'] == 'easy')
        med = sum(1 for r in results if r['difficulty'] == 'medium')
        hard = sum(1 for r in results if r['difficulty'] == 'hard')
        print(f"\n  Summary: {easy} easy, {med} medium, {hard} hard ({len(results)} total)")
    print()


def cmd_evidence(args, config):
    """Generate HTML evidence report with vision screenshots."""
    from src.reporter.evidence_report import generate_evidence_report
    
    base = Path(getattr(config, 'base_dir', '')) or Path(__file__).parent
    results_dir = base / 'data' / 'results'
    reports_dir = base / 'data' / 'reports'
    
    report_id = int(args.report)
    output = args.output or str(results_dir / f"evidence_{report_id}.html")
    
    try:
        out_path = generate_evidence_report(report_id, str(results_dir), str(reports_dir), output)
        print(f"✅ Evidence report generated: {out_path}")
        print(f"   Open in browser: file://{out_path}")
    except FileNotFoundError as e:
        print(f"❌ {e}")
    except Exception as e:
        print(f"❌ Error generating report: {e}")


def cmd_inspect(args, config):
    """Crawl and cache UI structure of a target application."""
    from playwright.sync_api import sync_playwright
    from src.browser.site_cache import SiteCache
    from src.auth.auth_manager import AuthManager

    target = args.target
    cache = SiteCache()

    # Delete existing cache if --fresh
    if args.fresh:
        cache_path = cache._cache_path(target)
        if cache_path.exists():
            cache_path.unlink()
            print(f"🗑️  Cleared existing cache for {target}")

    print(f"\n🔍 Inspecting target: {target}")
    print(f"   Cache dir: {cache.cache_dir}\n")

    # Set up auth if available
    auth_manager = _get_auth_manager(config)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=DEFAULT_CHROME_ARGS,
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )

        page = context.new_page()

        # Inject auth cookies if target matches a profile
        if auth_manager:
            try:
                from urllib.parse import urlparse
                target_domain = urlparse(target).netloc
                session = auth_manager.get_session(target_domain)
                if not session:
                    session = auth_manager.authenticate(target)
                if session and session.cookies:
                    cookies = []
                    for name, value in session.cookies.items():
                        cookies.append({
                            "name": name, "value": value,
                            "domain": urlparse(target).hostname,
                            "path": "/"
                        })
                    context.add_cookies(cookies)
                    print(f"  🔑 Injected auth cookies for {target_domain}")
            except Exception as e:
                print(f"  ⚠️ Auth injection failed: {e}")

        # Navigate to target
        try:
            page.goto(target, timeout=15000, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)  # Let SPA boot up
        except Exception as e:
            print(f"❌ Failed to load target: {e}")
            browser.close()
            return

        # Auto-dismiss common dialogs/overlays
        try:
            for selector in [
                "button:has-text('Dismiss')",
                "button:has-text('OK')",
                "button:has-text('Accept')",
                "button:has-text('Close')",
                ".close-dialog", ".cdk-overlay-backdrop",
            ]:
                if page.query_selector(selector):
                    page.click(selector, timeout=1000)
                    page.wait_for_timeout(300)
        except Exception:
            pass

        # Run the crawl
        data = cache.crawl(page, target, routes_to_visit=args.routes)

        browser.close()

    # Print summary
    routes = data.get("routes", {})
    endpoints = data.get("api_endpoints", {})

    print(f"\n{'='*60}")
    print(f"  📦 SITE CACHE: {target}")
    print(f"{'='*60}\n")

    print(f"  Pages inspected: {len([r for r in routes.values() if r.get('elements')])}")
    print(f"  API endpoints:   {len(endpoints)}")
    print()

    for route, info in routes.items():
        els = info.get("elements") or []
        inputs = [e for e in els if e.get("tag") in ("input", "textarea", "select", "mat-select")]
        buttons = [e for e in els if e.get("tag") == "button" or e.get("role") == "button"]
        links = [e for e in els if e.get("tag") == "a"]
        print(f"  {route}")
        print(f"    → {len(inputs)} inputs, {len(buttons)} buttons, {len(links)} links")
        for inp in inputs:
            label = inp.get("label") or inp.get("placeholder") or inp.get("id") or "?"
            sel = inp.get("selector") or "no selector"
            print(f"      📝 {label} ({sel})")
        for btn in buttons:
            text = btn.get("text", "?")[:40]
            sel = btn.get("selector") or "no selector"
            print(f"      🔘 {text} ({sel})")
        print()

    if endpoints:
        print("  API Endpoints:")
        for ep, info in endpoints.items():
            print(f"    → {ep}: {info.get('description', '')}")
        print()

    print(f"  💾 Saved to: {cache._cache_path(target)}")
    print()


def cmd_hunt(args, config):
    """Autonomous vulnerability hunting with browser-use agent."""
    import time as _time

    target = args.target
    vuln_types = args.vuln_types
    max_actions = args.max_actions
    verbose = args.verbose

    print(f"\n🔍 HUNT MODE — Autonomous Vulnerability Discovery")
    print(f"   Target: {target}")
    print(f"   Hunting for: {', '.join(vuln_types)}")
    print(f"   Max actions: {max_actions}")
    print()

    # Read keys from config YAML directly
    import yaml
    try:
        with open(os.path.join(getattr(config, 'base_dir', '.'), 'configs', 'config.yaml')) as _f:
            _raw = yaml.safe_load(_f) or {}
    except:
        _raw = {}

    groq_key = getattr(config, 'groq_api_key', '') or os.environ.get('GROQ_API_KEY', '')
    gemini_key = _raw.get('vision', {}).get('gemini_api_key', '') or os.environ.get('GEMINI_API_KEY', '')
    claude_key = _raw.get('vision', {}).get('claude_api_key', '') or \
                 _raw.get('claude_api_key', '') or os.environ.get('ANTHROPIC_API_KEY', '')

    # Provider priority: claude (best) > gemini (free) > groq
    if claude_key:
        bu_provider = 'claude'
        bu_model = 'claude-sonnet-4-0'
    elif gemini_key:
        bu_provider = 'gemini'
        bu_model = 'gemini-2.0-flash'
    elif groq_key:
        bu_provider = 'claude'
        bu_model = 'claude-sonnet-4-0'
    else:
        print("❌ No API key available for Browser-Use (need GEMINI_API_KEY, GROQ_API_KEY, or CLAUDE_API_KEY)")
        return

    print(f"   Provider: {bu_provider} ({bu_model})")

    # Auth setup
    auth_manager = None
    if args.auth_profile:
        from src.auth.auth_manager import AuthManager
        auth_manager = AuthManager(config)
        auth_session = auth_manager.get_session(args.auth_profile)
        if auth_session:
            print(f"   Auth: {args.auth_profile} ({auth_session.auth_type})")

    base = Path(getattr(config, 'base_dir', '')) or Path(__file__).parent

    from src.browser.browseruse_replayer import BrowserUseReplayer
    replayer = BrowserUseReplayer(
        api_key=gemini_key or groq_key or claude_key,
        model=bu_model,
        provider=bu_provider,
        headless=True,
        verbose=verbose,
        auth_manager=auth_manager,
        evidence_dir=str(base / 'data' / 'results'),
        blind=True,
        groq_api_key=groq_key,
        claude_api_key=claude_key,
    )

    # Run the hunt
    result = replayer.hunt(
        target_url=target,
        vuln_types=vuln_types,
        max_actions=max_actions,
    )

    # Print results
    findings = result['findings']
    print(f"\n{'='*60}")
    print(f"  🔍 HUNT RESULTS — {target}")
    print(f"{'='*60}")
    print(f"  Actions: {result['actions_taken']}")
    print(f"  Duration: {result['duration']}s")
    print(f"  Cost: ${result['cost']:.3f}")
    print(f"  Screenshots: {len(result['screenshots'])}")
    print()

    if findings:
        print(f"  🎯 VULNERABILITIES FOUND: {len(findings)}")
        print(f"  {'-'*50}")
        for i, f in enumerate(findings, 1):
            emoji = {
                'xss': '💉', 'sqli': '🗃️', 'idor': '🔓',
                'auth_bypass': '🚪', 'info_disclosure': '📋',
                'path_traversal': '📁', 'other': '⚠️'
            }.get(f['type'], '⚠️')
            print(f"  {emoji} #{i} [{f['type'].upper()}] {f['title']}")
            print(f"     Evidence: {f['evidence'][:120]}")
            print(f"     Payload: {f.get('payload', 'N/A')[:80]}")
            print(f"     Location: {f['location']}")
            print(f"     Found at step: {f.get('step', '?')}")
            print()
    else:
        print(f"  ⚪ No vulnerabilities found")
        print(f"  The agent explored {result['actions_taken']} actions without finding issues.")
        print()

    # Save findings to JSON
    findings_path = base / 'data' / 'results' / 'hunt_findings.json'
    with open(findings_path, 'w') as fp:
        json.dump(result, fp, indent=2, default=str)
    print(f"  Findings saved: {findings_path}")
    print(f"{'='*60}\n")


def cmd_recon(args, config):
    """Run LLM-powered site reconnaissance."""
    target = args.target
    verbose = getattr(args, 'verbose', False)
    fresh = getattr(args, 'fresh', False)

    # Check if we already have recon data
    if not fresh:
        from src.browser.site_cache import SiteCache
        cache = SiteCache()
        existing = cache.load(target)
        if existing and existing.get("recon_type") == "llm_agent":
            pages = len(existing.get("routes", {}))
            apis = len(existing.get("api_endpoints", {}))
            print(f"\n🗺️  Recon cache exists for {target}: {pages} pages, {apis} APIs")
            print(f"   Use --fresh to re-run recon from scratch")
            print(f"   Cache: {cache._cache_path(target)}")
            return

    print(f"\n🗺️  RECON — LLM-Powered Site Reconnaissance")
    print(f"   Target: {target}")
    print(f"   Max actions: {args.max_actions}")
    if args.focus:
        print(f"   Focus: {', '.join(args.focus)}")
    print()

    # Resolve API keys — prefer Groq (free) for recon
    groq_key = os.environ.get('GROQ_API_KEY', config.llm.api_key if config.llm.provider == 'groq' else None)
    claude_key = os.environ.get('CLAUDE_API_KEY', '')
    if not claude_key:
        import yaml
        try:
            with open(os.path.join(config.base_dir, 'configs', 'config.yaml')) as _f:
                _raw = yaml.safe_load(_f) or {}
                claude_key = _raw.get('vision', {}).get('claude_api_key', '')
        except Exception:
            pass

    # For recon, prefer cheap model
    if groq_key:
        recon_provider = 'groq'
        recon_model = 'meta-llama/llama-4-scout-17b-16e-instruct'
        recon_key = groq_key
    elif claude_key:
        recon_provider = 'claude'
        recon_model = 'claude-sonnet-4-0'
        recon_key = claude_key
    else:
        print("❌ No API key available (need GROQ_API_KEY or CLAUDE_API_KEY)")
        return

    print(f"   Provider: {recon_provider} ({recon_model})")

    auth_manager = _get_auth_manager(config)

    from src.browser.recon_agent import ReconAgent
    agent = ReconAgent(
        api_key=recon_key,
        model=recon_model,
        provider=recon_provider,
        headless=True,
        auth_manager=auth_manager,
        verbose=verbose,
        groq_api_key=groq_key,
        claude_api_key=claude_key,
    )

    result = agent.recon(target, max_actions=args.max_actions, focus_areas=args.focus)

    # Print results
    print(f"\n{'='*60}")
    print(f"  🗺️  RECON RESULTS — {target}")
    print(f"{'='*60}")
    print(f"  Duration: {result.duration:.1f}s")
    print(f"  Actions: {result.actions_taken}")
    if result.error:
        print(f"  ⚠️  Error: {result.error}")
    print()

    if result.pages:
        print(f"  📄 Pages ({len(result.pages)}):")
        for p in result.pages:
            ptype = p.get('page_type', 'content')
            print(f"    [{ptype:8s}] {p['url']}")
            if p.get('description'):
                print(f"             {p['description'][:80]}")

    if result.forms:
        print(f"\n  📝 Forms ({len(result.forms)}):")
        for f in result.forms:
            print(f"    {f['method']} {f['action']} — {f['fields_raw'][:80]}")

    if result.api_endpoints:
        print(f"\n  🔌 API Endpoints ({len(result.api_endpoints)}):")
        for ep in result.api_endpoints:
            print(f"    {ep['method']} {ep['endpoint']} — {ep.get('description', '')[:60]}")

    if result.auth_flow:
        af = result.auth_flow
        print(f"\n  🔑 Auth: {af.get('auth_type', '?')} at {af.get('login_url', '?')}")

    notes = result.site_map.get("notes", [])
    if notes:
        print(f"\n  📌 Notes ({len(notes)}):")
        for n in notes[:10]:
            print(f"    [{n.get('category', 'general')}] {n['note'][:80]}")

    # Save JSON
    json_path = result.save_json()
    print(f"\n  💾 Recon JSON: {json_path}")
    print(f"  💾 Site cache updated")
    print(f"\n  Next: python resurface.py replay --report ID --target {target} --browser")
    print(f"  The replay agent will automatically use this recon data.")
    print(f"{'='*60}\n")


def _run_recon_if_needed(target_url: str, config, verbose: bool = False):
    """Run recon if no cached data exists. Used by --recon flag in replay."""
    from src.browser.site_cache import SiteCache
    cache = SiteCache()
    existing = cache.load(target_url)
    if existing and existing.get("recon_type") == "llm_agent":
        pages = len(existing.get("routes", {}))
        apis = len(existing.get("api_endpoints", {}))
        print(f"  🗺️  Using cached recon: {pages} pages, {apis} APIs")
        return True

    print(f"  🗺️  Running recon first (no cached data for {target_url})...")
    groq_key = os.environ.get('GROQ_API_KEY', config.llm.api_key if config.llm.provider == 'groq' else None)
    claude_key = os.environ.get('CLAUDE_API_KEY', '')
    if not claude_key:
        import yaml
        try:
            with open(os.path.join(config.base_dir, 'configs', 'config.yaml')) as _f:
                _raw = yaml.safe_load(_f) or {}
                claude_key = _raw.get('vision', {}).get('claude_api_key', '')
        except Exception:
            pass

    if groq_key:
        recon_provider, recon_model, recon_key = 'groq', 'meta-llama/llama-4-scout-17b-16e-instruct', groq_key
    elif claude_key:
        recon_provider, recon_model, recon_key = 'claude', 'claude-sonnet-4-0', claude_key
    else:
        print("  ⚠️  No API key for recon — skipping")
        return False

    auth_manager = _get_auth_manager(config)
    from src.browser.recon_agent import ReconAgent
    agent = ReconAgent(
        api_key=recon_key, model=recon_model, provider=recon_provider,
        headless=True, auth_manager=auth_manager, verbose=verbose,
        groq_api_key=groq_key, claude_api_key=claude_key,
    )
    result = agent.recon(target_url, max_actions=20)
    print(f"  🗺️  Recon done: {result.summary()}")
    return not result.error


def cmd_generate(args, config):
    """Auto-generate vulnerability reports from target crawl."""
    from src.generator.report_generator import ReportGenerator

    target = args.target
    vuln_types = args.vuln_types
    start_id = args.start_id
    verbose = getattr(args, 'verbose', False)

    print(f"\n🏭 REPORT GENERATOR")
    print(f"   Target: {target}")
    print(f"   Vuln types: {', '.join(vuln_types)}")
    print(f"   Start ID: {start_id}")
    print()

    base = Path(getattr(config, 'base_dir', '')) or Path(__file__).parent
    output_dir = str(base / 'data' / 'reports')

    generator = ReportGenerator(output_dir=output_dir, verbose=verbose)

    if args.openapi:
        print(f"   📜 Generating from OpenAPI spec: {args.openapi}")
        reports = generator.generate_from_openapi(args.openapi, start_id=start_id)
    else:
        print(f"   🕷️  Crawling {target}...")
        reports = generator.generate_reports(target, vuln_types=vuln_types, start_id=start_id)

    if reports:
        print(f"\n✅ Generated {len(reports)} report(s):")
        for r in reports:
            print(f"   • {r['id']}: {r['title'][:60]}")
        print(f"\n   Reports saved to: {output_dir}/")
        print(f"   Parse them with: python resurface.py parse --all")
    else:
        print("   ⚠️  No reports generated — target may have no discoverable forms/endpoints")
    print()


def cmd_parallel_replay(args, config):
    """Replay multiple reports in parallel using browser-use agents."""
    from src.engine.parallel_browser_replayer import ParallelBrowserReplayer

    verbose = getattr(args, 'verbose', False)
    base = Path(getattr(config, 'base_dir', '')) or Path(__file__).parent
    parsed_dir = base / 'data' / 'parsed'
    results_dir = Path(config.reporter.output_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Determine which reports to replay
    if args.reports:
        report_ids = [int(r) for r in args.reports]
    else:
        report_ids = sorted([
            int(f.stem.replace('_parsed', ''))
            for f in parsed_dir.glob('*_parsed.json')
        ])

    if not report_ids:
        print("❌ No parsed reports found. Run 'parse' first.")
        return

    # Load parsed reports
    parsed_reports = []
    for rid in report_ids:
        pf = parsed_dir / f"{rid}_parsed.json"
        if pf.exists():
            with open(pf) as f:
                parsed_reports.append(_reconstruct_parsed_report(json.load(f)))
        else:
            print(f"  ⚠️  Skipping {rid} — no parsed file")

    if not parsed_reports:
        print("❌ No valid parsed reports to replay.")
        return

    # Resolve API keys
    groq_key = os.environ.get('GROQ_API_KEY', config.llm.api_key if config.llm.provider == 'groq' else None)
    claude_key = os.environ.get('CLAUDE_API_KEY', '')
    if not claude_key:
        import yaml
        try:
            with open(os.path.join(config.base_dir, 'configs', 'config.yaml')) as _f:
                _raw = yaml.safe_load(_f) or {}
                claude_key = _raw.get('vision', {}).get('claude_api_key', '')
        except Exception:
            pass

    if claude_key:
        bu_provider = 'claude'
        bu_model = 'claude-sonnet-4-0'
    elif groq_key:
        bu_provider = 'groq'
        bu_model = 'meta-llama/llama-4-scout-17b-16e-instruct'
    else:
        print("❌ No API key available for Browser-Use agent")
        return

    auth_manager = _get_auth_manager(config)

    print(f"\n⚡ PARALLEL REPLAY — {len(parsed_reports)} reports × concurrency {args.concurrency}")
    print(f"   Target: {args.target}")
    print(f"   Provider: {bu_provider} ({bu_model})")
    print(f"   Blind: {'yes' if args.blind else 'no'}")
    print()

    replayer = ParallelBrowserReplayer(
        api_key=claude_key or groq_key,
        model=bu_model,
        provider=bu_provider,
        headless=True,
        auth_manager=auth_manager,
        verbose=verbose,
        evidence_dir=str(results_dir),
        blind=getattr(args, 'blind', False),
        concurrency=args.concurrency,
        groq_api_key=groq_key,
        claude_api_key=claude_key,
    )

    import time as _time
    start = _time.time()
    results = replayer.replay_batch(parsed_reports, args.target)
    elapsed = _time.time() - start

    # Save results and print summary
    counters = {"vulnerable": 0, "fixed": 0, "partial": 0, "inconclusive": 0, "error": 0}
    for rr in results:
        status = rr.result.value if hasattr(rr.result, 'value') else str(rr.result)
        counters[status] = counters.get(status, 0) + 1
        # Save JSON
        result_data = {
            'report_id': rr.report_id, 'result': status,
            'confidence': rr.confidence, 'target': args.target,
            'analysis': rr.llm_analysis, 'duration_seconds': rr.duration_seconds,
            'replayed_at': rr.replayed_at.isoformat() if rr.replayed_at else None,
        }
        with open(results_dir / f"{rr.report_id}_result.json", 'w') as f:
            json.dump(result_data, f, indent=2)

    print(f"\n{'='*60}")
    print(f"  PARALLEL REPLAY COMPLETE — {elapsed:.1f}s total")
    print(f"{'='*60}")
    print(f"  🔴 Vulnerable:   {counters.get('vulnerable', 0)}")
    print(f"  🟢 Fixed:        {counters.get('fixed', 0)}")
    print(f"  🟡 Partial:      {counters.get('partial', 0)}")
    print(f"  ⚪ Inconclusive: {counters.get('inconclusive', 0)}")
    print(f"  ❌ Errors:       {counters.get('error', 0)}")
    print(f"  📊 Total:        {len(results)}")
    print(f"{'='*60}\n")


def cmd_benchmark(args, config):
    """Run comparison benchmark: same reports across multiple modes."""
    import csv
    import subprocess
    import time as _time

    target = args.target
    base = Path(getattr(config, 'base_dir', '')) or Path(__file__).parent
    parsed_dir = base / 'data' / 'parsed'
    results_dir = base / 'data' / 'results'
    results_dir.mkdir(parents=True, exist_ok=True)

    # Determine which reports to benchmark
    if args.reports:
        report_ids = [int(r) for r in args.reports]
    else:
        # All parsed reports
        report_ids = sorted([
            int(f.stem.replace('_parsed', ''))
            for f in parsed_dir.glob('*_parsed.json')
        ])

    if not report_ids:
        print("❌ No parsed reports found. Run 'parse' first.")
        return

    modes = args.modes
    verbose_flag = '--verbose' if args.verbose else ''

    print(f"\n📊 BENCHMARK — {len(report_ids)} reports × {len(modes)} modes")
    print(f"   Target: {target}")
    print(f"   Reports: {', '.join(str(r) for r in report_ids)}")
    print(f"   Modes: {', '.join(modes)}")
    print(f"   Output: {args.output}")
    print()

    # Load report metadata with auto difficulty scoring
    from src.utils.difficulty import score_report_difficulty
    report_meta = {}
    reports_dir = base / 'data' / 'reports'
    # App name map by report ID prefix
    APP_NAMES = {9001: 'Juice Shop', 9002: 'DVWA'}

    for rid in report_ids:
        parsed_path = parsed_dir / f"{rid}_parsed.json"
        report_path = reports_dir / f"{rid}.json"
        if parsed_path.exists():
            with open(parsed_path) as f:
                data = json.load(f)
            # Read original report for target_url / difficulty override
            report_data = {}
            if report_path.exists():
                with open(report_path) as f:
                    report_data = json.load(f)
            # Auto-score difficulty (respects explicit override in report JSON)
            diff_result = score_report_difficulty(
                str(report_path), str(parsed_path)
            )
            # Resolve per-report target: report JSON > CLI arg
            per_target = report_data.get('target_url') or target
            # Resolve app name
            app_key = rid // 100
            app_name = APP_NAMES.get(app_key, 'Unknown')

            report_meta[rid] = {
                'title': data.get('title', f'Report {rid}')[:50],
                'vuln_type': data.get('vuln_type', 'unknown'),
                'replay_method': data.get('replay_method', 'http'),
                'difficulty': diff_result['difficulty'],
                'diff_score': diff_result['score'],
                'target_url': per_target,
                'app': app_name,
            }

    # Run benchmarks
    all_results = []
    total_runs = len(report_ids) * len(modes)
    run_num = 0

    for rid in report_ids:
        meta = report_meta.get(rid, {'title': f'Report {rid}', 'vuln_type': '?', 'difficulty': '?'})

        for mode in modes:
            run_num += 1
            # Skip incompatible mode+method combos
            rmethod = meta.get('replay_method', 'http')
            if rmethod == 'browser' and mode in ('http', 'no-llm'):
                row = {
                    'report_id': rid, 'app': meta.get('app', '?'),
                    'title': meta['title'],
                    'vuln_type': meta['vuln_type'], 'difficulty': meta['difficulty'],
                    'mode': mode, 'result': 'skipped', 'confidence': 0,
                    'duration': 0, 'cost': 0,
                }
                all_results.append(row)
                print(f"  [{run_num}/{total_runs}] Report {rid} — mode: {mode} ⏭️  SKIPPED (browser-only report)", flush=True)
                continue

            print(f"  [{run_num}/{total_runs}] Report {rid} ({meta['vuln_type']}, {meta['difficulty']}) — mode: {mode}", flush=True)

            # Build command — use per-report target if available
            report_target = meta.get('target_url', target)
            cmd = [
                sys.executable, 'resurface.py', 'replay',
                '--report', str(rid),
                '--target', report_target,
            ]
            if verbose_flag:
                cmd.append('--verbose')

            if mode == 'no-llm':
                cmd.append('--no-llm')
            elif mode == 'browser-use':
                cmd.append('--browser')
            elif mode == 'browser-use-blind':
                cmd.extend(['--browser', '--blind'])
            # 'http' mode = default, no extra flags

            env = os.environ.copy()
            env['DISPLAY'] = os.environ.get('DISPLAY', ':99')

            start = _time.time()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=str(Path(__file__).parent),
                    env=env,
                )
                elapsed = _time.time() - start
                output = proc.stdout + proc.stderr

                # Parse result from output
                result = 'error'
                confidence = 0
                if 'VULNERABLE' in output:
                    result = 'vulnerable'
                elif 'FIXED' in output:
                    result = 'fixed'
                elif 'PARTIAL' in output:
                    result = 'partial'
                elif 'INCONCLUSIVE' in output:
                    result = 'inconclusive'

                # Parse confidence
                import re
                conf_match = re.search(r'Confidence:\s*(\d+)%', output)
                if conf_match:
                    confidence = int(conf_match.group(1))

                # Parse duration
                dur_match = re.search(r'Duration:\s*([\d.]+)s', output)
                duration = float(dur_match.group(1)) if dur_match else elapsed

                # Parse cost (vision runs)
                cost_match = re.search(r'~\$([\d.]+)', output)
                cost = float(cost_match.group(1)) if cost_match else 0.0

            except subprocess.TimeoutExpired:
                result = 'timeout'
                confidence = 0
                duration = 300.0
                cost = 0.0
            except Exception as e:
                result = 'error'
                confidence = 0
                duration = 0.0
                cost = 0.0

            # Result emoji
            emoji = {
                'vulnerable': '🔴',
                'fixed': '🟢',
                'partial': '🟡',
                'inconclusive': '⚪',
                'timeout': '⏰',
                'error': '❌',
            }.get(result, '?')

            row = {
                'report_id': rid,
                'app': meta.get('app', '?'),
                'title': meta['title'],
                'vuln_type': meta['vuln_type'],
                'difficulty': meta['difficulty'],
                'mode': mode,
                'result': result,
                'confidence': confidence,
                'duration': round(duration, 1),
                'cost': cost,
            }
            all_results.append(row)
            print(f"    {emoji} {result.upper()} ({confidence}%) — {duration:.1f}s" +
                  (f" — ${cost:.3f}" if cost > 0 else ""), flush=True)

    # Save CSV
    csv_path = Path(args.output)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'report_id', 'app', 'title', 'vuln_type', 'difficulty', 'mode',
            'result', 'confidence', 'duration', 'cost'
        ])
        writer.writeheader()
        writer.writerows(all_results)

    # Print summary table
    print(f"\n{'='*100}")
    print(f"  BENCHMARK RESULTS — {len(all_results)} runs")
    print(f"{'='*100}")
    print(f"  {'Report':<8} {'App':<12} {'Type':<16} {'Diff':<6} {'Mode':<15} {'Result':<14} {'Conf':>5} {'Time':>7} {'Cost':>7}")
    print(f"  {'-'*8} {'-'*12} {'-'*16} {'-'*6} {'-'*15} {'-'*14} {'-'*5} {'-'*7} {'-'*7}")
    for r in all_results:
        emoji = {'vulnerable': '🔴', 'fixed': '🟢', 'partial': '🟡',
                 'inconclusive': '⚪', 'timeout': '⏰', 'error': '❌',
                 'skipped': '⏭️'}.get(r['result'], '?')
        cost_str = f"${r['cost']:.3f}" if r['cost'] > 0 else "-"
        print(f"  {r['report_id']:<8} {r.get('app','?'):<12} {r['vuln_type']:<16} {r['difficulty']:<6} "
              f"{r['mode']:<15} {emoji} {r['result']:<12} {r['confidence']:>4}% "
              f"{r['duration']:>6.1f}s {cost_str:>7}")

    # Print mode comparison summary
    print(f"\n{'='*60}")
    print(f"  MODE COMPARISON SUMMARY")
    print(f"{'='*60}")
    for mode in modes:
        mode_results = [r for r in all_results if r['mode'] == mode]
        vuln = sum(1 for r in mode_results if r['result'] == 'vulnerable')
        fixed = sum(1 for r in mode_results if r['result'] == 'fixed')
        inconc = sum(1 for r in mode_results if r['result'] == 'inconclusive')
        total = len(mode_results)
        avg_dur = sum(r['duration'] for r in mode_results) / total if total else 0
        total_cost = sum(r['cost'] for r in mode_results)
        print(f"  {mode:<15}: {vuln}/{total} vulnerable, {fixed} fixed, "
              f"{inconc} inconclusive — avg {avg_dur:.1f}s" +
              (f", ${total_cost:.3f}" if total_cost > 0 else ""))

    # Difficulty breakdown
    print(f"\n{'='*60}")
    print(f"  DIFFICULTY × MODE")
    print(f"{'='*60}")
    for diff in ['easy', 'medium', 'hard']:
        for mode in modes:
            subset = [r for r in all_results if r['difficulty'] == diff and r['mode'] == mode
                      and r['result'] != 'skipped']
            if not subset:
                continue
            vuln = sum(1 for r in subset if r['result'] == 'vulnerable')
            fixed = sum(1 for r in subset if r['result'] == 'fixed')
            inconc = sum(1 for r in subset if r['result'] == 'inconclusive')
            total = len(subset)
            print(f"  {diff:<6} + {mode:<15}: {vuln}/{total} vulnerable, {fixed} fixed, {inconc} inconclusive")

    # App breakdown
    apps = sorted(set(r.get('app', '?') for r in all_results))
    if len(apps) > 1:
        print(f"\n{'='*60}")
        print(f"  APP × MODE")
        print(f"{'='*60}")
        for app in apps:
            for mode in modes:
                subset = [r for r in all_results if r.get('app') == app and r['mode'] == mode
                          and r['result'] != 'skipped']
                if not subset:
                    continue
                vuln = sum(1 for r in subset if r['result'] == 'vulnerable')
                total = len(subset)
                print(f"  {app:<12} + {mode:<15}: {vuln}/{total} vulnerable")

    total_cost = sum(r['cost'] for r in all_results)
    conclusive = [r for r in all_results if r['result'] not in ('skipped', 'error', 'timeout')]
    avg_dur = sum(r['duration'] for r in conclusive) / len(conclusive) if conclusive else 0
    print(f"\n  {len(all_results)} total runs, {len(conclusive)} conclusive — avg {avg_dur:.1f}s")
    print(f"  Total cost: ${total_cost:.3f}")
    print(f"  CSV saved: {csv_path}")
    print()


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
    parse_parser.add_argument('--verbose', '-v', action='store_true',
                             help='Print all LLM prompts and responses in real-time')
    
    # Replay command
    replay_parser = subparsers.add_parser('replay', help='Replay a parsed report')
    replay_parser.add_argument('--report', '-r', required=True, help='Report ID')
    replay_parser.add_argument('--target', '-t', required=True, help='Target URL')
    replay_parser.add_argument('--browser', '-b', action='store_true', 
                              help='Force browser-based replay using Browser-Use agent (DOM-indexed automation)')
    replay_parser.add_argument('--notify', action='store_true',
                              help='Send notifications on vulnerable findings')
    replay_parser.add_argument('--verbose', '-v', action='store_true',
                              help='Print all LLM prompts and responses in real-time')
    replay_parser.add_argument('--no-llm', dest='no_llm', action='store_true',
                              help='Use regex-only parsing and heuristic validation (baseline mode)')
    replay_parser.add_argument('--auto-auth', dest='auto_auth', action='store_true',
                              help='Enable LLM-driven autonomous authentication (auto signup/login)')
    replay_parser.add_argument('--cloud', action='store_true',
                              help='Use Browser-Use Cloud browser (remote, no local Chrome needed)')
    replay_parser.add_argument('--blind', action='store_true',
                              help='Blind mode: agent gets no URLs or step details, must navigate autonomously')
    replay_parser.add_argument('--fresh', action='store_true',
                              help='Ignore site cache (force fresh exploration)')
    replay_parser.add_argument('--enrich', '-e', action='store_true',
                              help='Enrich report with LLM-generated attack strategies before replay')
    replay_parser.add_argument('--retries', type=int, default=1,
                              help='Max attempts with post-failure refinement (requires --enrich, default: 1)')
    replay_parser.add_argument('--recon', action='store_true',
                              help='Run LLM recon agent first to learn the site (auto-skips if cache exists)')
    replay_parser.add_argument('--max-turns', type=int, default=None,
                              help='Maximum browser agent steps (overrides default MAX_ACTIONS)')
    replay_parser.add_argument('--max-cost', type=float, default=None,
                              help='Maximum USD spend before aborting')
    replay_parser.add_argument('--max-time', type=float, default=None,
                              help='Maximum wall-clock minutes before aborting')
    replay_parser.add_argument('--attempts', type=int, default=1,
                              help='Number of replay attempts with resume context (default: 1)')

    # Replay-all command
    replay_all_parser = subparsers.add_parser('replay-all',
                                              help='Parse and replay ALL reports against a target')
    replay_all_parser.add_argument('--target', '-t', required=True, help='Target URL')
    replay_all_parser.add_argument('--limit', '-l', type=int, default=None,
                                   help='Max reports to process')
    replay_all_parser.add_argument('--browser', '-b', action='store_true',
                                   help='Force browser-based replay using Browser-Use agent')
    replay_all_parser.add_argument('--async', dest='async_mode', action='store_true',
                                   help='Use async/parallel HTTP replay')
    replay_all_parser.add_argument('--parallel', dest='async_mode', action='store_true',
                                   help='Alias for --async')
    replay_all_parser.add_argument('--concurrency', type=int, default=5,
                                   help='Number of concurrent replays (default: 5)')
    replay_all_parser.add_argument('--notify', action='store_true',
                                   help='Send notifications on vulnerable findings')
    replay_all_parser.add_argument('--verbose', '-v', action='store_true',
                                   help='Print all LLM prompts and responses in real-time')
    replay_all_parser.add_argument('--no-llm', dest='no_llm', action='store_true',
                                   help='Use regex-only parsing and heuristic validation (baseline mode)')
    replay_all_parser.add_argument('--auto-auth', dest='auto_auth', action='store_true',
                                   help='Enable LLM-driven autonomous authentication (auto signup/login)')
    replay_all_parser.add_argument('--blind', action='store_true',
                                   help='Blind mode: agent gets no URLs or step details, must navigate autonomously')
    replay_all_parser.add_argument('--max-turns', type=int, default=None,
                                   help='Maximum browser agent steps per replay')
    replay_all_parser.add_argument('--max-cost', type=float, default=None,
                                   help='Maximum USD spend before aborting')
    replay_all_parser.add_argument('--max-time', type=float, default=None,
                                   help='Maximum wall-clock minutes before aborting')
    replay_all_parser.add_argument('--attempts', type=int, default=1,
                                   help='Number of replay attempts with resume context (default: 1)')

    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export results to summary report')
    export_parser.add_argument('--format', '-f', choices=['html', 'json'], default='html',
                               help='Output format (default: html)')

    # Difficulty command
    diff_parser = subparsers.add_parser('difficulty', help='Score report difficulty for automated replay')
    diff_parser.add_argument('--report', '-r', default=None, help='Report ID (default: all)')

    # Evidence command
    evidence_parser = subparsers.add_parser('evidence', help='Generate HTML evidence report with screenshots')
    evidence_parser.add_argument('--report', '-r', required=True, help='Report ID')
    evidence_parser.add_argument('--output', '-o', default=None,
                                 help='Output HTML path (default: data/results/evidence_<id>.html)')

    # Benchmark command
    bench_parser = subparsers.add_parser('benchmark', help='Run comparison benchmark across modes')
    bench_parser.add_argument('--target', '-t', default=None,
                              help='Target URL (optional — uses per-report target_url if set)')
    bench_parser.add_argument('--reports', '-r', nargs='+', 
                              help='Report IDs to benchmark (default: all parsed)')
    bench_parser.add_argument('--modes', '-m', nargs='+',
                              default=['http', 'no-llm'],
                              help='Modes to test: http, no-llm, browser-use, browser-use-blind (default: http no-llm)')
    bench_parser.add_argument('--verbose', '-v', action='store_true',
                              help='Show LLM prompts/responses')
    bench_parser.add_argument('--output', '-o', default='data/results/benchmark.csv',
                              help='CSV output path')

    # Hunt command — autonomous vulnerability discovery
    inspect_parser = subparsers.add_parser('inspect', help='Crawl and cache UI structure of a target (speeds up future replays)')
    inspect_parser.add_argument('--target', '-t', required=True, help='Target URL to inspect')
    inspect_parser.add_argument('--routes', nargs='+', default=None,
                                help='Specific routes to inspect (default: auto-discover)')
    inspect_parser.add_argument('--fresh', action='store_true',
                                help='Ignore existing cache and re-inspect from scratch')

    # Generate command — auto-generate reports from target crawl
    gen_parser = subparsers.add_parser('generate', help='Auto-generate vulnerability reports from target crawl')
    gen_parser.add_argument('--target', '-t', required=True, help='Target URL to crawl')
    gen_parser.add_argument('--vuln-types', nargs='+',
                            default=['xss_reflected', 'sqli', 'idor', 'privilege_escalation', 'info_disclosure'],
                            help='Vuln types to generate (default: xss_reflected sqli idor privilege_escalation info_disclosure)')
    gen_parser.add_argument('--start-id', type=int, default=990001,
                            help='Starting report ID (default: 990001)')
    gen_parser.add_argument('--openapi', default=None,
                            help='Generate from OpenAPI/Swagger spec URL instead of crawling')
    gen_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Parallel replay command
    par_parser = subparsers.add_parser('parallel-replay',
                                        help='Replay multiple reports in parallel using browser-use agents')
    par_parser.add_argument('--target', '-t', required=True, help='Target URL')
    par_parser.add_argument('--reports', '-r', nargs='+', default=None,
                            help='Report IDs (default: all parsed)')
    par_parser.add_argument('--concurrency', '-c', type=int, default=3,
                            help='Max simultaneous browser instances (default: 3)')
    par_parser.add_argument('--blind', action='store_true', help='Blind mode')
    par_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Recon command — LLM-powered site reconnaissance
    recon_parser = subparsers.add_parser('recon', help='LLM-powered site reconnaissance (Phase 1 — learn the site before attacking)')
    recon_parser.add_argument('--target', '-t', required=True, help='Target URL to recon')
    recon_parser.add_argument('--max-actions', type=int, default=25,
                              help='Max browser actions for recon (default: 25)')
    recon_parser.add_argument('--focus', nargs='+', default=None,
                              help='Focus areas: forms, api_endpoints, auth_flow, navigation')
    recon_parser.add_argument('--fresh', action='store_true',
                              help='Ignore existing recon cache and re-explore')
    recon_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    hunt_parser = subparsers.add_parser('hunt', help='Autonomously hunt for new vulnerabilities (browser-use agent)')
    hunt_parser.add_argument('--target', '-t', required=True, help='Target URL to hunt')
    hunt_parser.add_argument('--vuln-types', nargs='+',
                             default=['xss', 'sqli', 'idor', 'auth_bypass', 'info_disclosure'],
                             help='Vulnerability types to hunt for (default: xss sqli idor auth_bypass info_disclosure)')
    hunt_parser.add_argument('--max-actions', type=int, default=30,
                             help='Maximum actions for the agent (default: 30)')
    hunt_parser.add_argument('--verbose', '-v', action='store_true',
                             help='Show LLM prompts/responses')
    hunt_parser.add_argument('--auth-profile', default=None,
                             help='Auth profile name from config.yaml')
    hunt_parser.add_argument('--max-cost', type=float, default=None,
                             help='Maximum USD spend before aborting')
    hunt_parser.add_argument('--max-time', type=float, default=None,
                             help='Maximum wall-clock minutes before aborting')

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
        'difficulty': cmd_difficulty,
        'evidence': cmd_evidence,
        'benchmark': cmd_benchmark,
        'hunt': cmd_hunt,
        'inspect': cmd_inspect,
        'generate': cmd_generate,
        'parallel-replay': cmd_parallel_replay,
        'recon': cmd_recon,
    }
    
    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args, config)
    else:
        print(f"❌ Unknown command: {args.command}")
        arg_parser.print_help()


if __name__ == '__main__':
    main()
