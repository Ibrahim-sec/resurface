# Resurface Issues Log

*Created: 2026-02-05 after PortSwigger blind testing session*

## Critical Bugs

### 1. `capture_dom` tool broken — ✅ FIXED
- **Error:** `'Page' object has no attribute 'content'`
- **Location:** `src/browser/browseruse_replayer.py:929`
- **Impact:** Agent can't capture DOM snapshots for evidence
- **Fix:** Use JS eval `document.documentElement.outerHTML` instead of `page.content()`

### 2. Screenshot capture fails in `report_vulnerability` — ✅ FIXED (2026-02-07)
- **Error:** `Page.screenshot() got unexpected keyword argument 'format'`
- **Location:** `src/browser/browseruse_replayer.py:642`
- **Impact:** No screenshots saved with findings
- **Fix:** Changed to `page.screenshot(type='png', full_page=True)` — Playwright returns bytes directly

### 3. Groq tool calling incompatible with instructor — ✅ FIXED (2026-02-07)
- **Error:** Groq wraps tool params in `{"type": "string", "value": "..."}` instead of just the value
- **Impact:** Parsing with Groq fails completely
- **Fix:** Use `instructor.Mode.JSON` instead of default tool calling mode for Groq provider
- **Also fixed:** Default model ID updated to `meta-llama/llama-4-scout-17b-16e-instruct`

### 4. Enum `.value` calls on strings
- **Error:** `AttributeError: 'str' object has no attribute 'value'`
- **Location:** Multiple places in `resurface.py`
- **Status:** Fixed with `getattr(x, 'value', x)` pattern
- **Root cause:** `model_config = ConfigDict(use_enum_values=True)` was set inconsistently

---

## Agent Behavior Issues

### 5. Blind mode lacks systematic page exploration — ✅ FIXED (2026-02-07)
- **Problem:** Agent searches homepage exhaustively but doesn't click into sub-pages
- **Example:** DOM XSS lab had vulnerable select on product pages, not homepage. Agent never found it.
- **Impact:** Blind mode fails on multi-page apps where vuln is on sub-pages
- **Fix:** Added Phase 1 (Exploration) / Phase 2 (Testing) to blind prompt
  - Phase 1: Click 3-5 links to discover app structure before testing
  - Phase 2: Target the most promising page found
  - Added DOM XSS specific guidance for URL parameters

### 6. Stale lab state confusion — ✅ FIXED (2026-02-07)
- **Problem:** Previously solved lab shows "Solved" banner, agent gets confused
- **Impact:** Agent wastes steps trying to understand why lab is already solved
- **Fix:** Added instruction to ignore "Solved"/"Congratulations" banners in blind prompt

### 7. Form validation retry overhead — ✅ FIXED (2026-02-07)
- **Problem:** Agent submits forms without filling required fields, then has to retry
- **Impact:** Wastes 2-3 steps per form
- **Fix:** Added instruction to check for required fields before submitting forms

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
