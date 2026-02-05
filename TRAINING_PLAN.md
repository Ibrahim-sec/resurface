# Resurface — Training & Improvement Plan

## Goal
Systematically test the hunt mode and replay agent against multiple vulnerable platforms, identify false positives/negatives, and fix them until results are reliable.

## Phase 1: Hunt Mode Training (Juice Shop)
Run `hunt` against Juice Shop targeting each vuln type individually:

1. **XSS Hunt** — `--vuln-types xss --max-actions 25`
   - Expected: Find reflected XSS in search bar
   - Watch for: Agent clicking without typing (the main failure pattern)
   - Fix if needed: Improve prompt, tune nudge/force-type thresholds

2. **SQLi Hunt** — `--vuln-types sqli --max-actions 25`
   - Expected: Find SQLi in login form
   - Watch for: Agent can't find login page, or types in wrong fields
   - Fix if needed: Add "Account" / "Login" link detection to prompt

3. **Combined Hunt** — `--vuln-types xss sqli idor info_disclosure --max-actions 40`
   - Expected: Find multiple vulns in one run
   - Watch for: Agent gets stuck on one vuln type and never moves on
   - Fix if needed: Add "move on after finding" logic

## Phase 2: Hunt Mode Training (DVWA)
Same as Phase 1 but against DVWA (`http://localhost:4444`):
- DVWA has simpler UI — should be easier
- Need auth profile working (`--auth-profile dvwa`)
- Test: SQLi, XSS reflected, XSS stored, command injection, file inclusion

## Phase 3: Hunt Mode Training (More Platforms)
Deploy and test against additional targets:
- **WebGoat** — OWASP training app (Java-based)
- **bWAPP** — Buggy Web Application
- **HackTheBox/TryHackMe practice boxes** (if accessible)
- **Mutillidae** — OWASP Mutillidae II
- **PortSwigger Web Security Academy** — High priority

For each platform:
1. Deploy via Docker
2. Create auth profile in config.yaml
3. Run hunt mode
4. Document findings and false positives
5. Fix any issues found

## Phase 4: False Positive Analysis & Fixes
For each test run, classify results:

### False Positive Patterns to Watch
- [ ] Network intercept DATA_LEAK triggering on normal API responses
- [ ] Agent claiming vuln found but no actual evidence
- [ ] AUTH_SUCCESS triggering on non-login API calls
- [ ] LLM hallucinating findings without real evidence

### False Negative Patterns to Watch
- [ ] Agent clicking endlessly without typing payloads
- [ ] Agent can't navigate to the right page (login, search, etc.)
- [ ] Agent stuck in toggle loops (search bar open/close)
- [ ] Force-type selectors don't match the target app's DOM
- [ ] Agent gives up too early (done_hunting=true before testing)

### Fix Categories
1. **Prompt improvements** — Edit `src/prompts/playbooks/*.md`
2. **Safety net tuning** — Adjust nudge/force-type thresholds
3. **Network intercept refinement** — Tighter URL/body matching
4. **App-specific selectors** — Add common input selectors
5. **Multi-step strategies** — Teach agent to login first, then explore
6. **Evidence validation** — Cross-check LLM claims against actual data

## Phase 5: Benchmark Everything
After fixes, run full benchmark:
```bash
# All reports, all modes
python3 resurface.py benchmark --modes http no-llm browser-use browser-use-blind

# Hunt mode against each app
python3 resurface.py hunt --target http://localhost:3333 --max-actions 30
python3 resurface.py hunt --target http://localhost:4444 --max-actions 30 --auth-profile dvwa
```

Build final comparison matrix for FYP:
- Replay mode: easy vs hard × http vs no-llm vs browser-use-blind
- Hunt mode: findings per app, false positive rate, cost per finding
- Human baseline: how long would manual testing take?

## Code Quality Notes
- **browseruse_replayer.py is ~1285 lines** — Keep it focused on replay
- **Prompts are in src/prompts/** — Edit markdown files, not Python code
- **Structured output via instructor** — Use Pydantic models for LLM responses
- **Retries via tenacity** — Don't write manual retry loops

## Success Criteria
- Hunt mode finds ≥3 real vulns on Juice Shop in one run
- Hunt mode finds ≥2 real vulns on DVWA in one run
- False positive rate < 10% across all platforms
- No false negatives on known-vulnerable endpoints
- Agent types payloads within first 5 actions consistently
- instructor integration works end-to-end (no JSON parsing errors)
