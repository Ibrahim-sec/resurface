# Resurface Issues Log

*Created: 2026-02-05 after PortSwigger blind testing session*

## Critical Bugs

### 1. `capture_dom` tool broken
- **Error:** `'Page' object has no attribute 'content'`
- **Location:** `src/browser/browseruse_replayer.py:929`
- **Impact:** Agent can't capture DOM snapshots for evidence
- **Fix:** Update to use correct Playwright API (`page.content()` might need async)

### 2. Screenshot capture fails in `report_vulnerability`
- **Error:** `Page.screenshot() got an unexpected keyword argument 'path'`
- **Location:** `src/browser/browseruse_replayer.py:616`
- **Impact:** No screenshots saved with findings
- **Fix:** Check browser-use/Playwright API for correct screenshot params

### 3. Groq tool calling incompatible with instructor
- **Error:** Groq wraps tool params in `{"type": "string", "value": "..."}` instead of just the value
- **Impact:** Parsing with Groq fails completely
- **Fix:** Either use a different model for parsing, or add Groq-specific response unwrapping

### 4. Enum `.value` calls on strings
- **Error:** `AttributeError: 'str' object has no attribute 'value'`
- **Location:** Multiple places in `resurface.py`
- **Status:** Fixed with `getattr(x, 'value', x)` pattern
- **Root cause:** `model_config = ConfigDict(use_enum_values=True)` was set inconsistently

---

## Agent Behavior Issues

### 5. Blind mode lacks systematic page exploration
- **Problem:** Agent searches homepage exhaustively but doesn't click into sub-pages
- **Example:** DOM XSS lab had vulnerable select on product pages, not homepage. Agent never found it.
- **Impact:** Blind mode fails on multi-page apps where vuln is on sub-pages
- **Fix ideas:**
  - Add "explore all links" phase before testing
  - Use recon agent output to guide blind replay
  - Require clicking at least N distinct links before giving up

### 6. Stale lab state confusion
- **Problem:** Previously solved lab shows "Solved" banner, agent gets confused
- **Impact:** Agent wastes steps trying to understand why lab is already solved
- **Fix:** Ignore "Solved"/"Congratulations" banners during blind testing

### 7. Form validation retry overhead
- **Problem:** Agent submits forms without filling required fields, then has to retry
- **Impact:** Wastes 2-3 steps per form
- **Fix ideas:**
  - Pre-scan form for required fields before injecting payload
  - Fill all visible fields with dummy data by default

---

## Performance Issues

### 8. Groq/Llama too slow for recon
- **Problem:** Recon agent with Groq takes 3-5x longer than Claude
- **Impact:** Recon phase is painfully slow
- **Fix:** Use Claude for recon too, or optimize recon prompts for smaller models

---

## Completed Fixes (2026-02-05)

- [x] Pydantic v2 migration
- [x] instructor integration for structured output
- [x] LiteLLM + tenacity for unified LLM client
- [x] Extracted prompts to markdown files
- [x] Fixed bare `except:` clauses
- [x] Fixed enum `.value` AttributeError with getattr pattern
- [x] Committed refactor (28 files, 1583 insertions)

---

## Test Results Summary

| Lab | Mode | Result | Time | Notes |
|-----|------|--------|------|-------|
| Reflected XSS (basic) | Guided | ✅ VULN 100% | 72.8s | 4 steps |
| DOM XSS (select element) | Guided | ✅ VULN 90% | 88.5s | 5 steps |
| DOM XSS (select element) | Blind | ❌ FAILED | - | Stuck on homepage, didn't explore product pages |
| Stored XSS (comment) | Blind | ✅ VULN 95% | 236.4s | 14 steps, found it independently! |
