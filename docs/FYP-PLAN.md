# 📋 Resurface — FYP Project Plan

## Project Title
**"Resurface: An LLM-Powered Automated Vulnerability Regression Hunter Using Disclosed Bug Bounty Reports"**

## Alternative Titles (pick what your uni prefers)
- "Automated Vulnerability Regression Detection Through LLM-Based Bug Bounty Report Replay"
- "Leveraging Large Language Models for Autonomous Vulnerability Reproduction from Disclosed Security Reports"

---

## 1. Introduction & Background

### Problem
When organizations fix vulnerabilities reported through bug bounty programs, the fix isn't always permanent. Code refactors, new features, dependency updates, and deployment changes can reintroduce previously fixed vulnerabilities. This is known as **vulnerability regression**.

Bug bounty platforms like HackerOne publicly disclose resolved reports through their "Hacktivity" feed. These disclosures contain detailed vulnerability descriptions, proof-of-concept (PoC) steps, and expected outcomes. However:

- **No automated tool** exists that can read these unstructured reports and reproduce the PoC steps
- Manually re-testing hundreds of old reports is time-prohibitive
- Existing automation tools (Nuclei, Burp Suite) require **manually written templates** — they can't understand free-text reports
- The gap between "report disclosed" and "regression detected" can be months or years

### Opportunity
Large Language Models (LLMs) can now understand unstructured text, extract actionable steps, and even drive browser automation. This creates an opportunity to build a system that:
1. Reads disclosed bug bounty reports as-is (no manual template creation)
2. Understands the vulnerability type and reproduction steps
3. Autonomously replays the PoC against the target
4. Validates whether the vulnerability still exists

### Novelty
| Existing Approach | Limitation | Resurface's Advantage |
|---|---|---|
| Nuclei templates | Requires manual template writing | LLM reads raw reports directly |
| Burp Suite automation | Rule-based, no NLP understanding | Understands unstructured PoC text |
| PentestGPT / HackerGPT | Assistant-based (human in the loop) | Fully autonomous reproduction |
| Traditional regression testing | Tests code, not security behavior | Tests actual vulnerability presence |
| Vulnerability scanners (Nessus, etc.) | Signature-based detection | Context-aware reproduction from real PoCs |

---

## 2. Objectives

### Primary Objectives
1. Design and develop an automated system that scrapes publicly disclosed bug bounty reports
2. Implement an LLM-powered parser that extracts structured PoC steps from unstructured report text
3. Build a reproduction engine capable of replaying HTTP-based and browser-based PoCs
4. Create a validation mechanism that determines if a vulnerability has resurfaced
5. Generate detailed reports comparing original findings with current results

### Secondary Objectives
6. Support at least 4 vulnerability classes (XSS, IDOR, Open Redirect, SSRF)
7. Integrate browser automation for vulnerabilities requiring real browser interaction
8. Provide a dashboard for visualizing regression results across programs
9. Evaluate accuracy of LLM-based report parsing vs. manual parsing

---

## 3. Scope

### In Scope
- HackerOne Hacktivity (public disclosures) as primary data source
- Web application vulnerabilities (HTTP/browser-based)
- LLM-powered report parsing and understanding
- Autonomous PoC replay (HTTP requests + browser automation)
- Result validation and reporting
- Testing on intentionally vulnerable applications

### Out of Scope
- Mobile application vulnerabilities
- Binary/native exploitation
- Network-layer vulnerabilities
- Real-time scanning (this is replay-based, not discovery-based)
- Testing against unauthorized targets

---

## 4. Methodology

### Research Approach
**Design Science Research Methodology (DSRM)**
1. Problem identification (vulnerability regression gap)
2. Define objectives (automated replay system)
3. Design & development (Resurface tool)
4. Demonstration (demo against vulnerable apps)
5. Evaluation (accuracy, coverage, speed metrics)
6. Communication (FYP report + presentation)

### Development Approach
**Agile (2-week sprints)**

---

## 5. Detailed Timeline

### Sprint 1-2: Research & Foundation (Week 1-4)
**Deliverables:**
- Literature review complete
- HackerOne scraper working
- 100+ reports collected and stored
- Basic LLM prompt engineering for report parsing
- Report schema defined

**Tasks:**
- Research existing work (automated exploitation, LLM security tools, regression testing)
- Study HackerOne Hacktivity structure and access methods
- Build scraper (handle pagination, rate limiting, report extraction)
- Design report storage schema (SQLite)
- Experiment with LLM prompts for PoC extraction
- Document methodology

### Sprint 3-4: Parser & HTTP Engine (Week 5-8)
**Deliverables:**
- LLM parser extracts structured PoC from raw reports (>80% accuracy)
- HTTP replay engine handles IDOR, open redirect, SSRF
- Unit tests for parser and engine

**Tasks:**
- Build structured output format for parsed reports
- Implement PoC step extraction (endpoints, parameters, payloads, expected results)
- Build HTTP replay engine using httpx
- Handle authentication tokens, cookies, session management
- Implement IDOR reproduction logic
- Implement open redirect reproduction logic
- Implement SSRF reproduction logic (with callback server)
- Test against DVWA / bWAPP / custom vulnerable app

### Sprint 5-6: Browser Engine & Validation (Week 9-12)
**Deliverables:**
- Browser-based replay working for XSS/CSRF
- Validation layer compares expected vs actual results
- Evidence capture (screenshots, HAR files)

**Tasks:**
- Integrate Playwright
- Build LLM-driven browser agent (or integrate browser-use)
- Implement XSS reproduction (reflected: inject + check alert/DOM)
- Implement XSS reproduction (stored: inject + revisit + verify)
- Implement CSRF reproduction (craft form + submit + verify state change)
- Build validation engine (LLM compares original expected behavior vs actual)
- Implement evidence capture (screenshots, network logs)
- Build bypass detection (partial fix identification)

### Sprint 7: Reporting & Dashboard (Week 13)
**Deliverables:**
- HTML/JSON report generation
- Web dashboard
- CLI interface complete

**Tasks:**
- Build report generator (HTML template with evidence)
- Build simple dashboard (Streamlit)
- Finalize CLI commands
- End-to-end integration testing

### Sprint 8: Demo & Documentation (Week 14)
**Deliverables:**
- Demo environment ready
- FYP report complete
- Presentation ready

**Tasks:**
- Set up intentionally vulnerable demo app with known bugs
- Create sample disclosed reports for demo
- Record demo video
- Finalize FYP paper
- Prepare presentation slides

---

## 6. Evaluation Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Parsing Accuracy** | % of reports correctly parsed into structured PoC | >80% |
| **Reproduction Rate** | % of parsed reports successfully replayed | >70% |
| **True Positive Rate** | % of actual vulnerabilities correctly identified | >85% |
| **False Positive Rate** | % of fixed vulns incorrectly flagged as present | <15% |
| **Time Efficiency** | Time to replay vs manual reproduction | >5x faster |
| **Vuln Class Coverage** | Number of vulnerability classes supported | ≥4 |

---

## 7. Expected Contributions

1. **Novel system design** — first tool to autonomously reproduce vulnerabilities from unstructured bug bounty reports using LLM
2. **LLM prompt engineering framework** — reusable prompts for security report parsing
3. **Browser-based PoC automation** — LLM-driven browser agent for web vulnerability reproduction
4. **Regression detection methodology** — systematic approach to identifying vulnerability regressions
5. **Open-source tool** — available for community use and further research

---

## 8. Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| LLM parsing inaccuracy | Core functionality affected | Few-shot prompting, fine-tuning, fallback to pattern matching |
| HackerOne blocks scraping | No data source | Cache reports, use API, manual collection backup |
| Browser automation instability | XSS/CSRF replay fails | Fallback to HTTP-only testing, retry logic |
| Ethical/legal concerns | Project rejection | Test only on own apps, clear disclaimer, ethics board approval |
| Time constraints | Incomplete features | Prioritize MVP (HTTP replay first, browser second) |
| LLM API costs | Budget overrun | Use efficient prompting, cache responses, use cheaper models for simple tasks |

---

## 9. References (Starting Points)

- HackerOne Hacktivity: https://hackerone.com/hacktivity
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Playwright documentation: https://playwright.dev/python/
- browser-use (LLM browser automation): https://github.com/browser-use/browser-use
- Nuclei (template-based scanner): https://github.com/projectdiscovery/nuclei
- Research papers on automated vulnerability detection & LLM security applications

---

*This plan is a living document. Update as the project evolves.*
