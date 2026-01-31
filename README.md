# 🔄 Resurface

**Automated Vulnerability Regression Hunter — LLM-Powered Bug Bounty Report Replay Engine**

Resurface reads disclosed bug bounty reports (HackerOne, etc.), extracts PoC steps using an LLM, and autonomously replays them against targets to detect if vulnerabilities have resurfaced or can be bypassed.

> _"Bugs don't die. They resurface."_

---

## 🎯 Problem Statement

Bug bounty programs publicly disclose resolved vulnerability reports. However:
- Vulnerabilities frequently **regress** after code changes, refactors, or new feature deployments
- **Bypass variants** of fixed vulnerabilities are among the most common findings
- Manually re-testing hundreds of old disclosed reports is impractical
- No existing tool can read **unstructured human-written reports** and autonomously reproduce them

## 💡 Solution

Resurface uses Large Language Models to:
1. **Scrape** disclosed reports from bug bounty platforms (HackerOne Hacktivity)
2. **Parse** unstructured report text into structured PoC reproduction steps
3. **Replay** the PoC autonomously — via HTTP requests or LLM-driven browser automation
4. **Validate** whether the vulnerability still exists, is fixed, or is partially mitigated
5. **Report** findings with evidence and comparison to the original report

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    RESURFACE                         │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│  │ Scraper  │───▶│  Parser  │───▶│   Engine     │  │
│  │          │    │  (LLM)   │    │              │  │
│  │ HackerOne│    │          │    │ ┌──────────┐ │  │
│  │ Hacktivity│   │ Extract: │    │ │ HTTP     │ │  │
│  │ API/Web  │    │ - Vuln   │    │ │ Replayer │ │  │
│  │          │    │   type   │    │ └──────────┘ │  │
│  │          │    │ - Target │    │ ┌──────────┐ │  │
│  │          │    │ - Steps  │    │ │ Browser  │ │  │
│  │          │    │ - PoC    │    │ │ Agent    │ │  │
│  │          │    │ - Expect │    │ │(Playwright│ │  │
│  └──────────┘    └──────────┘    │ │+ LLM)   │ │  │
│                                  │ └──────────┘ │  │
│                                  └──────┬───────┘  │
│                                         │          │
│                                  ┌──────▼───────┐  │
│                                  │  Validator   │  │
│                                  │   (LLM)     │  │
│                                  │              │  │
│                                  │ Compare:     │  │
│                                  │ Expected vs  │  │
│                                  │ Actual       │  │
│                                  └──────┬───────┘  │
│                                         │          │
│                                  ┌──────▼───────┐  │
│                                  │  Reporter    │  │
│                                  │              │  │
│                                  │ - Dashboard  │  │
│                                  │ - JSON/HTML  │  │
│                                  │ - Evidence   │  │
│                                  └──────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 📂 Project Structure

```
resurface/
├── src/
│   ├── scraper/        # HackerOne report collection
│   ├── parser/         # LLM-powered report parsing
│   ├── engine/         # Reproduction engine (HTTP + browser)
│   ├── browser/        # Playwright + LLM browser automation
│   ├── validator/      # Result validation & comparison
│   └── reporter/       # Output generation (dashboard, reports)
├── tests/              # Unit & integration tests
├── docs/               # Documentation & FYP paper resources
├── configs/            # Configuration files
├── data/
│   ├── reports/        # Scraped/stored disclosed reports
│   └── results/        # Replay results & evidence
├── scripts/            # Utility scripts
├── requirements.txt
└── README.md
```

## 🎯 Supported Vulnerability Classes (MVP)

| Class | Reproduction Method | Priority |
|-------|-------------------|----------|
| Reflected XSS | Browser Agent | 🔴 High |
| Stored XSS | Browser Agent | 🔴 High |
| IDOR | HTTP Replayer | 🔴 High |
| Open Redirect | HTTP Replayer | 🟡 Medium |
| SSRF | HTTP Replayer | 🟡 Medium |
| CSRF | Browser Agent | 🟡 Medium |
| Information Disclosure | HTTP Replayer | 🟢 Low |
| SQL Injection | HTTP Replayer | 🟢 Low |

## 🗓️ Development Roadmap (1 Semester)

### Phase 1: Foundation (Week 1-3)
- [ ] HackerOne Hacktivity scraper (public disclosed reports)
- [ ] Report storage & indexing system
- [ ] Basic LLM integration (OpenAI/Claude API)
- [ ] Report parser: extract vuln type, target, PoC steps

### Phase 2: HTTP Replay Engine (Week 4-6)
- [ ] HTTP-based PoC replayer (requests/httpx)
- [ ] LLM-guided step execution for HTTP vulns
- [ ] IDOR reproduction module
- [ ] Open redirect reproduction module
- [ ] SSRF reproduction module

### Phase 3: Browser Replay Engine (Week 7-9)
- [ ] Playwright integration
- [ ] LLM-driven browser agent (browser-use or custom)
- [ ] XSS reproduction module (reflected + stored)
- [ ] CSRF reproduction module
- [ ] Screenshot/video evidence capture

### Phase 4: Validation & Reporting (Week 10-12)
- [ ] LLM-powered result validation (compare expected vs actual)
- [ ] Bypass detection (partial fix identification)
- [ ] HTML/JSON report generation
- [ ] Web dashboard for results visualization
- [ ] Evidence packaging (screenshots, request/response logs)

### Phase 5: Polish & Demo (Week 13-14)
- [ ] Demo environment setup (intentionally vulnerable app)
- [ ] End-to-end testing
- [ ] Documentation & FYP paper
- [ ] Presentation preparation

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **LLM:** OpenAI GPT-4 / Anthropic Claude (via API)
- **HTTP Engine:** httpx / requests
- **Browser Automation:** Playwright + browser-use
- **Scraping:** BeautifulSoup / Scrapy
- **Storage:** SQLite (reports & results)
- **Dashboard:** Streamlit or FastAPI + simple frontend
- **CLI:** Click / Typer

## 🚀 Quick Start

```bash
# Install
pip install -r requirements.txt
playwright install

# Configure
cp configs/example.yaml configs/config.yaml
# Add your LLM API key

# Scrape reports
resurface scrape --platform hackerone --program <program-name> --limit 50

# Parse & replay
resurface replay --report <report-id> --target <url>

# Replay all reports for a program
resurface replay-all --program <program-name> --target <url>

# Generate report
resurface report --format html --output results/
```

## ⚖️ Ethical Use

This tool is designed for:
- ✅ Security teams testing their own applications for regressions
- ✅ Bug bounty hunters testing programs that **explicitly allow automated testing**
- ✅ Research & educational purposes on intentionally vulnerable applications
- ❌ NOT for unauthorized testing against any target

## 📄 License

MIT

## 👤 Author

Ibrahim — Bug Bounty Hunter & Cybersecurity Researcher
Final Year Project — 2026

---

*Built with the belief that bugs don't die — they resurface.*
