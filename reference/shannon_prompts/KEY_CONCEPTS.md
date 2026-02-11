# Shannon Prompt Key Concepts

Extracted from KeygraphHQ/shannon for Resurface inspiration.

## 1. Proof Levels (from XSS exploit prompt)

```
Level 1 - Payload Blocked/Encoded
  → Evidence: Payload reflected but encoded/sanitized
  → Classification: NOT VULNERABLE

Level 2 - Payload Injected But Blocked  
  → Evidence: Payload in HTML but JS execution prevented by filters/CSP
  → Classification: POTENTIAL (requires bypass)

Level 3 - JavaScript Execution Confirmed
  → Evidence: JavaScript executes (alert, console.log, DOM manipulation)
  → Classification: EXPLOITED

Level 4 - Critical Impact Demonstrated
  → Evidence: Session hijacking, data theft, unauthorized actions
  → Classification: EXPLOITED (CRITICAL)
```

## 2. Verdict Classifications

```
EXPLOITED           → Successfully demonstrated impact
BLOCKED_BY_SECURITY → Valid vuln but blocked by WAF/controls  
OUT_OF_SCOPE        → Requires internal access
FALSE_POSITIVE      → Not actually vulnerable
UNPROVEN            → Theoretical, no demonstration
```

## 3. Core Principles

### Proof-Based Exploitation
- **Claims require evidence**: Every claim backed by demonstrable proof
- **Assumptions must be validated**: Test every assumption
- **Failures must be documented**: Create detailed bug reports
- **Default to skepticism**: Assume NOT vulnerable until proven
- **Partial results are not complete**: Be honest about achieved vs attempted

### Methodical Progression
1. Confirm vulnerability exists
2. Analyze defenses (WAF, CSP, filters)
3. Craft bypass
4. Execute impact-oriented payload
5. Document evidence

## 4. Agent Role Definition Pattern

```xml
<role>
You are a world-class [VULN TYPE] Exploitation Specialist. 
You are not an analyst; you are an active penetration tester.
Your persona is methodical, persistent, and laser-focused on 
proving the tangible impact of vulnerabilities.
</role>

<objective>
Your mission is to systematically and exhaustively weaponize 
**every single potential [VULN TYPE] vulnerability** provided to you.
Success criterion: A comprehensive evidence report for **every vulnerability**
</objective>

<critical>
### PROOF-BASED EXPLOITATION REQUIREMENTS
[Detailed requirements...]

### RIGOROUS VERIFICATION FRAMEWORK  
[Verification steps...]
</critical>
```

## 5. Intelligence-Driven Exploitation

Before exploitation, read these files in order:
1. `pre_recon_deliverable.md` - Architecture, code snippets, DB details
2. `recon_deliverable.md` - API inventory, input vectors
3. `[vuln]_analysis_deliverable.md` - Strategic context, WAF behavior

**Key insight**: Don't blind test. Use intelligence from recon phase.

## 6. SQLi Exploitation Methodology (from injection prompt)

```
Phase 1: CONFIRM
- Error-based detection: ', ", --, ;
- Boolean-based: ' AND '1'='1 vs ' AND '1'='2
- Time-based: ' AND SLEEP(5)--

Phase 2: ENUMERATE  
- Database type detection
- Column count enumeration
- Table/column discovery

Phase 3: EXFILTRATE
- UNION-based extraction
- Error-based extraction
- Blind extraction
```

## 7. XSS Bypass Techniques (from xss prompt)

```
CSP Bypasses:
- Check for 'unsafe-inline'
- Look for allowed domains with JSONP
- Check for base-uri missing
- Angular/Vue template injection if CSP allows

WAF Bypasses:
- Case variation: <ScRiPt>
- Event handlers: onerror, onload, onfocus
- Encoding: HTML entities, URL encoding
- Polyglots: javascript:, data:
```

## 8. Evidence Documentation Pattern

```markdown
## Vulnerability: [ID]
### Target: [URL/Endpoint]
### Payload Used:
\`\`\`
[exact payload]
\`\`\`
### Evidence:
[screenshot/response/extracted data]
### Impact:
[what an attacker could do]
### Classification: [EXPLOITED/BLOCKED/etc]
```

## Ideas for Resurface

1. **Add proof levels to our validation** - Currently we just say VULN/NOT_VULN. Add nuance.

2. **Add verdict classifications** - BLOCKED_BY_SECURITY is useful for "patched but we tried"

3. **Use intelligence-driven replay** - Parse report fully before replaying, not blind

4. **Structured evidence output** - Our evidence chain is good, but could use Shannon's format

5. **Agent role prompts** - Their role definitions are very clear and focused
