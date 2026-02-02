# Resurface — Project Status

**Last updated**: 2026-02-02
**What**: LLM-powered vulnerability regression & bypass hunter — parses bug bounty reports, replays PoCs via browser automation, uses AI mutation to find WAF bypasses, and auto-generates evidence chains. (FYP 2026)
**Owner**: Ibrahim

## Quick Start

```bash
export DISPLAY=:99
cd /root/resurface
source venv/bin/activate

# Phase 1: Recon (learn the site — uses Groq, free)
python3 resurface.py recon --target http://localhost:3333

# Phase 2: Replay with browser agent (uses Claude for accuracy)
python3 resurface.py replay --report 900109 --target http://localhost:3333 --browser

# Combined: auto-recon + replay
python3 resurface.py replay --report 900109 --target http://localhost:3333 --browser --recon

# HTTP replay (fast, no browser)
python3 resurface.py replay --report 900102 --target http://localhost:3333

# Blind mode (agent gets no URLs/steps, must explore)
python3 resurface.py replay --report 900111 --target http://localhost:3333 --browser --blind

# With enrichment + retry
python3 resurface.py replay --report 900109 --target http://localhost:3333 --browser --enrich --retries 3

# Parallel replay (3 browsers at once)
python3 resurface.py parallel-replay --target http://localhost:3333 --concurrency 3

# Auto-generate reports from target
python3 resurface.py generate --target http://localhost:3333

# No-LLM baseline (for FYP comparison)
python3 resurface.py replay-all --target http://localhost:3333 --no-llm

# Benchmark across modes
python3 resurface.py benchmark --target http://localhost:3333 --modes http no-llm browser-use browser-use-blind

# Hunt mode (autonomous, no reports)
python3 resurface.py hunt --target http://localhost:3333 --vuln-types xss sqli idor
```

## Architecture

```
resurface.py (CLI — 17 commands, 2035 lines)
│
├── src/parser/
│   ├── llm_parser.py              # LLM parses reports → structured data
│   └── regex_parser.py            # Regex-only baseline (--no-llm)
│
├── src/enricher/
│   └── report_enricher.py         # Pre-flight recon + LLM attack strategies
│
├── src/browser/
│   ├── browseruse_replayer.py     # Browser-Use agent (~1250 lines, 13 tools)
│   ├── recon_agent.py             # LLM-powered two-phase recon (871 lines)
│   ├── site_cache.py              # Site knowledge cache (605 lines)
│   └── __init__.py                # DEFAULT_CHROME_ARGS constant
│
├── src/engine/
│   ├── http_replayer.py           # HTTP replay engine
│   ├── mutation_engine.py         # LLM payload mutation / WAF bypass
│   ├── browser_waf_bypass.py      # WAF bypass integration for browser agent
│   ├── parallel_browser_replayer.py # Concurrent browser replays
│   ├── async_replayer.py          # Async HTTP replay
│   └── session_manager.py         # Cookie/CSRF session chaining
│
├── src/evidence/
│   └── evidence_chain.py          # Structured evidence timeline + HTML reports
│
├── src/chain/
│   └── vuln_chain.py              # Multi-step exploit chains + checkpoints
│
├── src/generator/
│   └── report_generator.py        # Auto-generate reports from target crawl
│
├── src/validator/
│   ├── llm_validator.py           # LLM result validation
│   └── regex_validator.py         # Pattern-matching baseline (--no-llm)
│
├── src/payloads/
│   └── payload_library.py         # 164 curated payloads (5 vuln types)
│
├── src/recon/
│   └── target_profiler.py         # Tech stack fingerprinting
│
├── src/auth/
│   ├── auth_manager.py            # Auth profiles (JWT/cookie/OAuth2)
│   ├── auth_config.py             # Auth config parsing
│   └── auto_auth.py               # LLM-driven autonomous auth
│
├── src/reporter/
│   ├── summary_report.py          # HTML summary dashboard
│   └── evidence_report.py         # Per-report evidence HTML
│
├── configs/
│   └── config.yaml                # Main config
│
└── data/
    ├── reports/                   # Vulnerability reports (JSON)
    ├── parsed/                    # LLM-parsed structured reports
    ├── results/                   # Results + screenshots + evidence chains
    ├── payloads/                  # Curated payload files
    └── site_cache/                # Cached site recon data
```

## Browser Agent Tools (13)

| # | Tool | Description |
|---|------|-------------|
| 1 | `report_vulnerability` | Report finding + auto-screenshot + evidence chain |
| 2 | `save_note` | Persist credentials/tokens across steps |
| 3 | `get_note` | Recall saved credentials/tokens |
| 4 | `make_request` | HTTP requests with cookie sync (like Burp Repeater) |
| 5 | `check_response` | Analyze response for vuln indicators |
| 6 | `auto_login` | One-click auth from configured profile |
| 7 | `capture_dom` | Snapshot page HTML as evidence |
| 8 | `get_payloads` | Curated payloads by vuln type |
| 9 | `mutate_payload` | WAF bypass variant generation |
| 10 | `test_bypass` | Test bypass payload via HTTP |
| 11 | `checkpoint` | Mark exploit chain step complete |
| 12 | `chain_status` | Check exploit chain progress |

## Two-Phase Replay Flow

```
Phase 1: RECON (Groq — free)          Phase 2: ATTACK (Claude — accurate)
┌──────────────────────┐              ┌──────────────────────┐
│ LLM explores target  │              │ Agent has full site   │
│ Maps pages, forms,   │──saves to──▶│ knowledge. Goes       │
│ APIs, auth flow      │  SiteCache  │ directly to relevant  │
│ NO payloads injected │              │ pages and attacks.    │
└──────────────────────┘              └──────────────────────┘
```

## Test Environment

| Target | URL | Auth | Reports |
|--------|-----|------|---------|
| Juice Shop | `http://localhost:3333` | SQLi login → admin JWT | 900101-900116 |
| DVWA | `http://localhost:4444` | admin/password, security=low | 900201-900212 |
| noVNC | `http://185.218.124.252:6081/vnc.html` | — | — |

## Results Summary (Juice Shop)

| Mode | VULNERABLE | FIXED | PARTIAL | INCONCLUSIVE |
|------|-----------|-------|---------|-------------|
| No-LLM (regex) | 0 | 0 | 0 | 9 + 1 FP |
| LLM (HTTP) | 7 | 2 | 1 | 0 |
| Browser-Use (easy) | Tested ✅ | — | — | — |
| Browser-Use (hard/blind) | 8/8 (100%) | — | — | — |

## What's Working
- HTTP replayer + LLM validation: 100% accuracy on Juice Shop easy reports
- Browser-Use agent: XSS, SQLi, priv esc confirmed in 5-12 steps
- Auth engine: SQLi login → JWT injection → authenticated requests
- Blind mode: 8/8 hard reports solved (100%) — proves LLM adds genuine value
- All new modules compile clean (evidence chain, WAF bypass, vuln chains, parallel replay, recon, generator)

## What Needs Testing
- Evidence chain integration (auto-logs to HTML reports)
- WAF bypass tools in browser agent (mutate_payload, test_bypass)
- Vuln chain checkpoint/resume flow
- Parallel replay with multiple browsers
- Recon agent (Phase 1 → Phase 2 data flow)
- Report generator output quality
- PortSwigger Web Security Academy labs

## Known Issues
- DVWA browser auth fails (CSRF token not handled)
- Groq free tier rate limits (500K TPD)
- Gemini API keys all exhausted
- New modules untested against real targets
