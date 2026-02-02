# 🔄 Resurface

**LLM-Powered Vulnerability Regression & Bypass Hunter for Bug Bounty**

Resurface parses disclosed bug bounty reports, autonomously replays them against targets using LLM-driven browser automation, detects WAF/filter blocking and generates bypass variants, and produces structured evidence chains — all from a single CLI.

> _"Bugs don't die. They resurface."_

---

## 🎯 What It Does

1. **Parse** — LLM reads unstructured vulnerability reports and extracts structured PoC steps
2. **Recon** — LLM agent explores the target site to learn its structure before attacking
3. **Replay** — Browser-Use agent reproduces the vulnerability via DOM-indexed automation
4. **Bypass** — When payloads are blocked (WAF/filters), mutation engine generates bypass variants
5. **Validate** — LLM analyzes results to determine: VULNERABLE, FIXED, PARTIAL, or INCONCLUSIVE
6. **Evidence** — Structured evidence chains with screenshots, DOM snapshots, and HTML reports

## 🏗️ Architecture

```
                    ┌─────────────┐
                    │   Reports   │  (HackerOne, manual, auto-generated)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Parser    │  LLM extracts vuln type, steps, payloads
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Enricher   │  Pre-flight recon + attack strategies
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼───┐ ┌──────▼──────┐
       │ Recon Agent  │ │ HTTP │ │ Browser-Use │
       │ (Phase 1)    │ │      │ │  (Phase 2)  │
       │ Learn site   │ │      │ │ 13 tools    │
       └──────┬───────┘ └──┬───┘ └──────┬──────┘
              │            │            │
              │   ┌────────▼────────┐   │
              └──▶│   Site Cache    │◀──┘
                  └────────┬────────┘
                           │
                    ┌──────▼──────┐
                    │  Validator  │  LLM or regex baseline
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼───┐ ┌──────▼──────┐
       │  Evidence   │ │ JSON │ │   HTML      │
       │   Chain     │ │      │ │  Reports    │
       └─────────────┘ └──────┘ └─────────────┘
```

## 🚀 Quick Start

```bash
cd /root/resurface
source venv/bin/activate
export DISPLAY=:99

# Recon a target (Phase 1 — learn the site)
python3 resurface.py recon --target http://localhost:3333

# Replay a vulnerability report (Phase 2 — attack)
python3 resurface.py replay --report 900109 --target http://localhost:3333 --browser

# Combined: recon + replay in one command
python3 resurface.py replay --report 900109 --target http://localhost:3333 --browser --recon

# Blind mode (agent gets no URLs/steps)
python3 resurface.py replay --report 900111 --target http://localhost:3333 --browser --blind

# With enrichment + retries
python3 resurface.py replay --report 900109 --target http://localhost:3333 --browser --enrich --retries 3

# HTTP-only replay (fast, no browser)
python3 resurface.py replay --report 900102 --target http://localhost:3333

# Parallel replay (multiple browsers)
python3 resurface.py parallel-replay --target http://localhost:3333 -c 3

# Auto-generate reports from a target
python3 resurface.py generate --target http://localhost:3333

# Autonomous hunt (no reports needed)
python3 resurface.py hunt --target http://localhost:3333

# Benchmark comparison
python3 resurface.py benchmark --modes http no-llm browser-use browser-use-blind

# No-LLM baseline (FYP comparison)
python3 resurface.py replay-all --target http://localhost:3333 --no-llm
```

## 🛠️ CLI Commands

| Command | Description |
|---------|-------------|
| `scrape` | Scrape disclosed reports from HackerOne |
| `list` | List available reports |
| `parse` | Parse reports with LLM (or regex with `--no-llm`) |
| `replay` | Replay a single report (`--browser`, `--blind`, `--enrich`, `--recon`, `--cloud`) |
| `replay-all` | Replay all reports (`--async`, `--parallel`) |
| `parallel-replay` | Multiple browser agents concurrently (`-c 3`) |
| `recon` | LLM-powered site reconnaissance (Phase 1) |
| `generate` | Auto-generate vuln reports from target crawl |
| `hunt` | Autonomous vulnerability discovery |
| `inspect` | Crawl & cache UI structure (Playwright, no LLM) |
| `benchmark` | Cross-mode comparison with CSV output |
| `evidence` | Generate HTML evidence report with screenshots |
| `stats` | Database statistics |
| `export` | Export results as HTML/JSON |
| `difficulty` | Score report difficulty |

## 🤖 Browser Agent Tools

The browser-use agent has 13 tools available during replay:

| Tool | What It Does |
|------|-------------|
| `report_vulnerability` | Report finding + auto-screenshot + evidence chain |
| `save_note` / `get_note` | Persist & recall credentials across steps |
| `make_request` | HTTP requests with cookie sync (like Burp Repeater) |
| `check_response` | Analyze response for vuln indicators |
| `auto_login` | One-click auth from config profile |
| `capture_dom` | Snapshot page HTML |
| `get_payloads` | Curated payloads by vuln type |
| `mutate_payload` | Generate WAF bypass variants |
| `test_bypass` | Test bypass payload, get blocked/not-blocked verdict |
| `checkpoint` / `chain_status` | Multi-step exploit chain tracking |

## 🔬 Two-Phase Replay

**Phase 1 — Recon** (cheap, uses Groq):
- LLM agent explores the target
- Maps pages, forms, APIs, auth flows
- No payloads injected — observation only
- Results cached in SiteCache

**Phase 2 — Attack** (accurate, uses Claude):
- Agent has full site knowledge from Phase 1
- Goes directly to relevant pages
- Executes exploit chain with checkpoint tracking
- Auto-generates evidence chain with screenshots

## 📊 Results

### Juice Shop (10 easy + 8 hard reports)

| Mode | Easy (10) | Hard (8) |
|------|-----------|----------|
| HTTP + no-LLM (regex) | 0 vulnerable | 0/8 |
| HTTP + LLM | 7 vulnerable, 2 fixed, 1 partial | 0/8 inconclusive |
| Browser-Use + Blind | — | **8/8 vulnerable (100%)** |

The hard reports contain NO URLs, NO payloads, NO steps — just a vulnerability type and description. Only the LLM-driven browser agent can solve them.

## 🎯 Supported Vulnerability Types

| Type | HTTP | Browser | Blind |
|------|------|---------|-------|
| Reflected XSS | ✅ | ✅ | ✅ |
| Stored XSS | — | ✅ | ✅ |
| SQL Injection | ✅ | ✅ | ✅ |
| IDOR | ✅ | ✅ | ✅ |
| Privilege Escalation | ✅ | ✅ | ✅ |
| Info Disclosure | ✅ | ✅ | ✅ |
| Broken Access Control | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ✅ | ✅ |
| Open Redirect | ✅ | ✅ | ✅ |

## 🛡️ WAF Bypass Pipeline

When a payload is blocked:
1. **Heuristic detection** — checks for 403, stripped payloads, WAF signatures
2. **LLM analysis** — identifies what specific filter blocked the payload
3. **Variant generation** — produces bypass payloads (encoding tricks, tag alternatives, case manipulation)
4. **Automated testing** — tests each variant via HTTP
5. **Browser confirmation** — successful bypass used in browser for full exploitation

## 🛠️ Tech Stack

- **Python 3.11+** (venv at `/root/resurface/venv`)
- **Browser Automation**: browser-use v0.11.7 (DOM-indexed, CDP)
- **LLM (browser)**: Claude Sonnet 4 via Anthropic API
- **LLM (text/recon)**: Groq free tier (Llama 4 Scout)
- **HTTP**: httpx (async)
- **Browser**: Google Chrome + Xvfb (headless with VNC viewing)
- **Storage**: SQLite + JSON files
- **Config**: YAML

## ⚖️ Ethical Use

This tool is designed for:
- ✅ Security teams testing their own applications for regressions
- ✅ Bug bounty hunters testing programs that explicitly allow automated testing
- ✅ Research & education on intentionally vulnerable applications (Juice Shop, DVWA, PortSwigger)
- ❌ NOT for unauthorized testing against any target

## 📄 License

MIT

## 👤 Author

Ibrahim — Bug Bounty Hunter & Cybersecurity Researcher
Final Year Project — 2026
