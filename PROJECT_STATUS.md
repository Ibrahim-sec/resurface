# Resurface — Project Status

**Last updated**: 2026-02-04  
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

# No-LLM baseline (for FYP comparison)
python3 resurface.py replay-all --target http://localhost:3333 --no-llm

# Hunt mode (autonomous, no reports)
python3 resurface.py hunt --target http://localhost:3333 --vuln-types xss sqli idor
```

## Architecture

```
resurface.py (CLI — 17 commands, ~2200 lines)
│
├── src/llm/                       # NEW: Unified LLM client
│   ├── __init__.py
│   └── client.py                  # LiteLLM + instructor + tenacity
│
├── src/prompts/                   # NEW: Extracted prompt templates
│   ├── __init__.py                # Prompt loader with caching
│   ├── parse_report.md
│   ├── validate_result.md
│   ├── mutation_analysis.md
│   ├── block_detection.md
│   └── playbooks/                 # Per-vuln-type strategies
│       ├── xss_reflected.md
│       ├── sqli.md
│       ├── privilege_escalation.md
│       ├── idor.md
│       ├── info_disclosure.md
│       └── generic.md
│
├── src/models.py                  # Pydantic v2 models + structured output schemas
│
├── src/parser/
│   ├── llm_parser.py              # Uses instructor for structured output
│   └── regex_parser.py            # Regex-only baseline (--no-llm)
│
├── src/validator/
│   ├── llm_validator.py           # Uses instructor for structured output
│   └── regex_validator.py         # Heuristic baseline (--no-llm)
│
├── src/enricher/
│   └── report_enricher.py         # Pre-flight recon + LLM attack strategies
│
├── src/browser/
│   ├── browseruse_replayer.py     # Browser-Use agent (~1285 lines, 13 tools)
│   ├── recon_agent.py             # LLM-powered two-phase recon (871 lines)
│   ├── site_cache.py              # Site knowledge cache (605 lines)
│   └── __init__.py                # DEFAULT_CHROME_ARGS constant
│
├── src/engine/
│   ├── http_replayer.py           # HTTP replay engine
│   ├── mutation_engine.py         # Uses instructor for structured WAF bypass
│   ├── browser_waf_bypass.py      # WAF bypass integration for browser agent
│   ├── parallel_browser_replayer.py
│   ├── async_replayer.py
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
├── src/payloads/
│   └── payload_library.py         # 164 curated payloads (5 vuln types)
│
├── src/auth/
│   ├── auth_manager.py            # Auth profiles (JWT/cookie/OAuth2)
│   ├── auth_config.py
│   └── auto_auth.py               # LLM-driven autonomous auth
│
└── configs/
    ├── config.yaml                # Main config (gitignored)
    └── config.example.yaml        # Template without API keys
```

## Tech Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| LLM Abstraction | LiteLLM | Unified API for Groq/Claude/Gemini/OpenAI |
| Structured Output | instructor | Guaranteed Pydantic models from LLM |
| Retry Logic | tenacity | Exponential backoff on rate limits |
| Data Models | Pydantic v2 | Validation + JSON schema generation |
| Browser Automation | browser-use v0.11.7 | DOM-indexed, not coordinate-based |
| HTTP Client | httpx | Async support |
| LLM (browser) | Claude Sonnet 4 | Most accurate, ~$0.02/run |
| LLM (text/recon) | Groq (Llama 4 Scout) | Free tier, 500K TPD |
| Storage | SQLite + JSON | Simple, no external DB |

## Structured Output Models

New Pydantic schemas for guaranteed LLM output:

| Model | Purpose |
|-------|---------|
| `LLMParsedReport` | Parse vulnerability reports |
| `LLMValidationResult` | Validate replay results |
| `LLMBlockDetection` | Detect WAF/filter blocking |
| `LLMMutationAnalysis` | Generate bypass variants |
| `LLMValueExtraction` | Extract session values |

## Browser Agent Tools (13)

| # | Tool | Description |
|---|------|-------------|
| 1 | `report_vulnerability` | Report finding + auto-screenshot + evidence chain |
| 2 | `save_note` | Persist credentials/tokens across steps |
| 3 | `get_note` | Recall saved credentials/tokens |
| 4 | `make_request` | HTTP requests with cookie sync |
| 5 | `check_response` | Analyze response for vuln indicators |
| 6 | `auto_login` | One-click auth from configured profile |
| 7 | `capture_dom` | Snapshot page HTML as evidence |
| 8 | `get_payloads` | Curated payloads by vuln type |
| 9 | `mutate_payload` | WAF bypass variant generation |
| 10 | `test_bypass` | Test bypass payload via HTTP |
| 11 | `checkpoint` | Mark exploit chain step complete |
| 12 | `chain_status` | Check exploit chain progress |

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
| Browser-Use (hard/blind) | **8/8 (100%)** | — | — | — |

## Recent Changes (2026-02-04)

### Major Refactor
- **Pydantic v2 models** — All dataclasses converted for validation + JSON schema
- **instructor integration** — Structured LLM output with guaranteed Pydantic models
- **LiteLLM + tenacity** — Unified LLM client with automatic retries
- **Prompts extracted** — All prompts now in `src/prompts/*.md` files
- **Fixed bare excepts** — All 17 bare `except:` clauses fixed
- **New files**: `src/llm/`, `src/prompts/`, `LICENSE`, `configs/config.example.yaml`

### Dependencies Added
- `litellm>=1.30.0` — Unified LLM API
- `instructor` — Structured output
- `tenacity` — Retry logic (was installed, now used)
- `typer` — Modern CLI (ready for future refactor)

## What's Working
- HTTP replayer + LLM validation: 100% accuracy on Juice Shop easy reports
- Browser-Use agent: XSS, SQLi, priv esc confirmed in 5-12 steps
- Auth engine: SQLi login → JWT injection → authenticated requests
- Blind mode: 8/8 hard reports solved (100%) — proves LLM adds genuine value
- Structured output: instructor guarantees valid Pydantic from LLM
- Retry logic: tenacity handles rate limits automatically

## What Needs Testing
- instructor integration with browser-use replay (end-to-end)
- Evidence chain integration (auto-logs to HTML reports)
- WAF bypass tools in browser agent
- Parallel replay with multiple browsers
- Recon agent (Phase 1 → Phase 2 data flow)

## Known Issues
- Claude credits exhausted (need to top up)
- DVWA browser auth fails (CSRF token not handled)
- Groq free tier rate limits (500K TPD)
- Docker containers need restart: `docker start juice-shop dvwa`
