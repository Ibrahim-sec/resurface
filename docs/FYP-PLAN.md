# 📋 Resurface — FYP Project Plan

## Project Title
**"Resurface: An LLM-Powered Automated Vulnerability Regression & Bypass Hunter Using Disclosed Bug Bounty Reports"**

## Alternative Titles
- "Automated Vulnerability Regression Detection and Bypass Discovery Through LLM-Based Bug Bounty Report Replay"
- "Leveraging Large Language Models for Autonomous Vulnerability Reproduction and Bypass Generation from Disclosed Security Reports"

---

## 1. Introduction & Background

### Problem
When organizations fix vulnerabilities reported through bug bounty programs, the fix isn't always permanent. Code refactors, new features, dependency updates, and deployment changes can reintroduce previously fixed vulnerabilities. This is known as **vulnerability regression**.

Bug bounty platforms like HackerOne publicly disclose resolved reports through their "Hacktivity" feed. These disclosures contain detailed vulnerability descriptions, proof-of-concept (PoC) steps, and expected outcomes. However:

- **No automated tool** exists that can read these unstructured reports and reproduce the PoC steps
- Manually re-testing hundreds of old reports is time-prohibitive
- Existing automation tools (Nuclei, Burp Suite) require **manually written templates** — they can't understand free-text reports
- The gap between "report disclosed" and "regression detected" can be months or years
- Even when a fix is confirmed, **no tool autonomously attempts to bypass it** using AI-generated payload mutations

### Opportunity
Large Language Models (LLMs) can now understand unstructured text, extract actionable steps, and drive browser automation. This creates an opportunity for a system that:
1. Reads disclosed bug bounty reports as-is (no manual template creation)
2. Understands the vulnerability type and reproduction steps
3. **Reconnoitres the target** to learn its structure before attacking
4. Autonomously replays the PoC against the target via browser automation
5. Validates whether the vulnerability still exists
6. When a fix is detected, uses LLM-driven mutation to **generate and test bypass variants**
7. Produces structured evidence chains with screenshots and HTML reports

### Novelty
| Existing Approach | Limitation | Resurface's Advantage |
|---|---|---|
| Nuclei templates | Requires manual template writing | LLM reads raw reports directly |
| Burp Suite automation | Rule-based, no NLP understanding | Understands unstructured PoC text |
| PentestGPT / HackerGPT | Assistant-based (human in the loop) | Fully autonomous reproduction |
| Traditional regression testing | Tests code, not security behavior | Tests actual vulnerability presence |
| Vulnerability scanners (Nessus, etc.) | Signature-based detection | Context-aware reproduction from real PoCs |
| Static wordlist fuzzers | Fixed payloads, no context awareness | LLM analyzes the specific fix and generates targeted bypass mutations |
| Manual penetration testing | Time-consuming, doesn't scale | Two-phase recon+attack with site knowledge caching |

---

## 2. Objectives

### Primary Objectives
1. Design and develop an automated system that parses publicly disclosed bug bounty reports
2. Implement an LLM-powered parser that extracts structured PoC steps from unstructured report text
3. Build a reproduction engine capable of replaying HTTP-based and browser-based PoCs
4. Implement a two-phase approach: LLM recon (learn the site) → LLM attack (exploit with knowledge)
5. Create a validation mechanism that determines if a vulnerability has resurfaced
6. Build an adaptive WAF bypass pipeline using LLM-driven payload mutation

### Secondary Objectives
7. Support 9+ vulnerability classes (XSS reflected/stored, SQLi, IDOR, privilege escalation, info disclosure, broken access control, path traversal, open redirect)
8. Provide structured evidence chains with screenshots, DOM snapshots, and HTML reports
9. Enable multi-step exploit chains with checkpoint/resume for complex vulnerabilities
10. Demonstrate parallel browser replay for batch testing
11. Evaluate accuracy via side-by-side comparison: LLM vs regex-only baseline

---

## 3. Scope

### In Scope
- Web application vulnerabilities (HTTP/browser-based)
- LLM-powered report parsing and understanding
- Two-phase replay: recon → attack
- Autonomous PoC replay (HTTP + browser-use DOM-indexed automation)
- WAF/filter bypass via LLM mutation engine
- Structured evidence collection and HTML reporting
- Multi-step exploit chain tracking
- Testing on intentionally vulnerable applications (Juice Shop, DVWA, PortSwigger)
- Comparison with regex-only baseline (--no-llm mode)

### Out of Scope
- Mobile application vulnerabilities
- Binary/native exploitation
- Network-layer vulnerabilities
- Real-time discovery scanning (this is replay-based)
- Testing against unauthorized targets

---

## 4. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      RESURFACE                           │
├──────────┬──────────┬───────────┬───────────┬───────────┤
│  Parser  │ Enricher │   Recon   │  Browser  │  WAF      │
│  (LLM)   │ (LLM)    │  Agent    │  Agent    │  Bypass   │
│          │          │ (Phase 1) │ (Phase 2) │  Engine   │
│ Extract  │ Attack   │ Learn     │ 13 tools  │ Mutation  │
│ vuln type│ strate-  │ site map  │ DOM-based │ + variant │
│ + steps  │ gies     │ forms,API │ automation│ testing   │
├──────────┴──────────┴─────┬─────┴───────────┴───────────┤
│                           │                              │
│              ┌────────────▼────────────┐                 │
│              │   Evidence Chain        │                 │
│              │   + Vuln Chain          │                 │
│              │   (timeline tracking)   │                 │
│              └────────────┬────────────┘                 │
│                           │                              │
│              ┌────────────▼────────────┐                 │
│              │  Validator (LLM/regex)  │                 │
│              │  + HTML Report Export   │                 │
│              └─────────────────────────┘                 │
└─────────────────────────────────────────────────────────┘
```

### Component Summary (17 CLI commands, ~8,000 lines of core code)

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| CLI | `resurface.py` | 2,035 | 17 commands, argument parsing, orchestration |
| Browser Agent | `browseruse_replayer.py` | 1,250 | DOM-indexed browser automation, 13 tools |
| Recon Agent | `recon_agent.py` | 871 | Two-phase site reconnaissance |
| Report Generator | `report_generator.py` | 678 | Auto-generate vuln reports from crawl |
| Site Cache | `site_cache.py` | 605 | Persistent site knowledge cache |
| Evidence Chain | `evidence_chain.py` | 569 | Structured evidence + HTML reports |
| WAF Bypass | `browser_waf_bypass.py` | 518 | Mutation engine for browser context |
| Vuln Chain | `vuln_chain.py` | 454 | Multi-step exploit chains |
| Mutation Engine | `mutation_engine.py` | ~400 | LLM payload mutation |
| Parallel Replay | `parallel_browser_replayer.py` | 205 | Concurrent browser instances |

### Browser Agent Tools (13)
1. `report_vulnerability` — Report finding + auto-screenshot + evidence chain
2. `save_note` / `get_note` — Persist & recall credentials across steps
3. `make_request` — HTTP requests with cookie sync (like Burp Repeater)
4. `check_response` — Analyze response for vuln indicators
5. `auto_login` — One-click auth from config profile
6. `capture_dom` — Snapshot page HTML
7. `get_payloads` — Curated payloads by vuln type (164 payloads)
8. `mutate_payload` — Generate WAF bypass variants
9. `test_bypass` — Test bypass payload with blocked/not-blocked verdict
10. `checkpoint` / `chain_status` — Multi-step exploit chain tracking

---

## 5. Key Innovation: Two-Phase Replay

**Phase 1 — Recon (Groq — free):**
The LLM agent explores the target purely to learn it. No payloads, no attacks. Discovers pages, forms, APIs, auth flows, tech stack. Results cached for reuse.

**Phase 2 — Attack (Claude — accurate):**
With full site knowledge, the agent goes directly to relevant pages and executes a targeted exploit chain. Evidence is captured at every step.

**Why this matters:**
- Phase 1 eliminates blind exploration (saves ~60-80% of attack agent's steps)
- Phase 1 uses cheap/free LLM (Groq), Phase 2 uses accurate LLM (Claude)
- Site knowledge persists across reports — recon once, attack many times
- Essential for unfamiliar targets (PortSwigger labs, real-world apps)

---

## 6. Evaluation Results

### Juice Shop (10 easy + 8 hard reports)

| Mode | Easy (10) | Hard (8) | Cost |
|------|-----------|----------|------|
| HTTP + no-LLM (regex) | 0 vulnerable, 1 FP | 0/8 inconclusive | $0 |
| HTTP + LLM | 7 vulnerable, 2 fixed, 1 partial | 0/8 inconclusive | ~$0.01 |
| Browser-Use + Blind | — | **8/8 vulnerable (100%)** | ~$0.46 |

**Key finding:** Hard reports (no URLs, no payloads, no steps — just vuln type + description) are **impossible** for HTTP/regex (0% detection) but the LLM browser agent solves them at 100%. This is the core evidence that LLM adds genuine value.

### Report 900109 — Privilege Escalation

| Metric | Before (old agent) | After (new agent) |
|--------|-------------------|------------------|
| Duration | 222s | 192s |
| Steps | 15 (hit budget) | 12 |
| Result | FAIL (forgot password) | ✅ 100% confidence |

---

## 7. Evaluation Metrics

| Metric | Description | Target | Achieved |
|--------|-------------|--------|----------|
| **Parsing Accuracy** | % of reports correctly parsed | >80% | ✅ ~95% |
| **Reproduction Rate** | % of parsed reports successfully replayed | >70% | ✅ 80% (HTTP), 100% (browser blind) |
| **True Positive Rate** | % of actual vulns correctly identified | >85% | ✅ 100% (Juice Shop) |
| **False Positive Rate** | % of fixed vulns incorrectly flagged | <15% | ✅ 0% (LLM mode) |
| **Time Efficiency** | Time vs manual reproduction | >5x faster | ✅ ~10x (HTTP), ~3x (browser) |
| **Vuln Class Coverage** | Vulnerability types supported | ≥4 | ✅ 9 types |

---

## 8. FYP Defense Points

### Must Show
1. **LLM vs no-LLM comparison** — The money shot: 0% vs 100% on hard reports
2. **Easy vs hard mode** — Hard reports prove LLM is essential
3. **Two-phase recon** — Agent learns site first, then attacks efficiently
4. **WAF bypass pipeline** — mutate_payload → test_bypass → confirm in browser
5. **Evidence chain HTML** — Professional-looking proof of exploitation
6. **Multi-step chain tracking** — checkpoint/resume for complex vulns
7. **Cost analysis** — ~$0.02 per browser replay with Claude

### Be Honest About
- Reports were handcrafted for Juice Shop (not real HackerOne disclosures)
- Only tested against 2 controlled targets (Juice Shop, DVWA)
- New modules (evidence chain, WAF bypass, recon) haven't been battle-tested yet
- Browser agent can still get stuck on unfamiliar UIs
- Real-world WAFs may be harder to bypass than lab environments

---

## 9. Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| LLM parsing inaccuracy | Core functionality affected | Few-shot prompting, Groq fallback, regex baseline |
| Browser automation instability | Replay fails | Retry logic, enrichment refinement, parallel replay |
| Ethical/legal concerns | Project rejection | Test only on own apps + authorized labs |
| LLM API costs | Budget overrun | Groq (free) for recon/parsing, Claude only for browser |
| Time constraints | Incomplete features | MVP first (HTTP + browser), extras later |
| New features untested | Demo failure | Test against Juice Shop before defense |

---

## 10. Next Steps

1. **Test all new features** against Juice Shop (evidence chain, WAF bypass, vuln chains, recon)
2. **Test recon agent** — Phase 1 → Phase 2 data flow validation
3. **PortSwigger labs** — Prove generalization beyond Juice Shop/DVWA
4. **Benchmark dashboard** — HTML visualization of benchmark CSV
5. **Confidence calibration** — Run same report 5x, measure consistency
6. **Write FYP report** — Architecture, methodology, results, analysis, limitations

---

*This plan is a living document. Last updated: 2026-02-02.*
