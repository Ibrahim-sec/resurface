#!/usr/bin/env python3
"""Fix generic indicators in all playbook files with vuln-specific ones."""

import os
import re
from pathlib import Path

# Category-specific indicators of success
INDICATORS = {
    "xss_reflected": """### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization""",

    "xss_stored": """### Indicators of Success
- Payload stored and rendered to other users
- JavaScript executes on page load
- Payload persists across sessions
- Other users affected when viewing content
- No output encoding on stored data""",

    "cross-site-scripting": """### Indicators of Success
- Payload reflected/stored without encoding
- JavaScript executes in browser context
- alert()/print()/document.cookie accessible
- DOM manipulation successful
- No WAF block or sanitization""",

    "sqli": """### Indicators of Success
- SQL syntax errors reveal injection point
- UNION SELECT returns additional data
- Boolean conditions change response
- Time delays confirm blind injection
- Database contents extracted""",

    "auth_bypass": """### Indicators of Success
- Access granted without valid credentials
- Session token accepted for different user
- Admin panel accessible
- Authentication step skipped
- User context changed to target account""",

    "broken_access_control": """### Indicators of Success
- Unauthorized resource accessed
- Other user's data visible
- Admin functionality available to regular user
- IDOR allows accessing other records
- Horizontal/vertical privilege escalation""",

    "access-control": """### Indicators of Success
- Unauthorized resource accessed
- Other user's data visible  
- Admin functionality available to regular user
- IDOR allows accessing other records
- Horizontal/vertical privilege escalation""",

    "csrf": """### Indicators of Success
- State-changing action performed without user consent
- No CSRF token required or token bypassable
- Forged request accepted by server
- Victim's account modified via attacker page
- SameSite cookie restrictions bypassed""",

    "ssrf": """### Indicators of Success
- Internal IP/port responds through application
- Cloud metadata endpoint accessed (169.254.169.254)
- DNS lookup to attacker server received
- Internal services enumerated
- Localhost/127.0.0.1 accessible""",

    "xxe": """### Indicators of Success
- External entity resolved
- Local file contents returned (/etc/passwd)
- DNS/HTTP callback received (blind XXE)
- DTD fetched from external server
- Error messages reveal file contents""",

    "ssti": """### Indicators of Success
- Template expression evaluated (7*7=49)
- Server-side code execution confirmed
- OS command output visible
- Template engine identified
- File read/write or RCE achieved""",

    "server-side-template-injection": """### Indicators of Success
- Template expression evaluated (7*7=49)
- Server-side code execution confirmed
- OS command output visible
- Template engine identified (Jinja2, Tornado, etc.)
- File read/write or RCE achieved""",

    "deserialization": """### Indicators of Success
- Serialized payload processed without error
- Code execution via gadget chain
- File created/deleted on server
- Out-of-band callback received
- Server behavior indicates deserialization""",

    "file_upload": """### Indicators of Success
- Malicious file uploaded successfully
- Web shell accessible via URL
- Code execution confirmed
- File extension restriction bypassed
- Content-Type validation bypassed""",

    "file-upload": """### Indicators of Success
- Malicious file uploaded successfully
- Web shell accessible and executes code
- File extension restriction bypassed
- Content-Type validation bypassed
- Server-side code execution confirmed""",

    "path_traversal": """### Indicators of Success
- File outside webroot accessed
- /etc/passwd or similar file contents returned
- Directory traversal sequences not filtered
- Null byte or encoding bypass works
- Sensitive configuration files exposed""",

    "file-path-traversal": """### Indicators of Success
- File outside webroot accessed
- /etc/passwd contents returned
- ../ sequences traverse directories
- Encoding bypass successful
- Sensitive files exposed""",

    "os-command-injection": """### Indicators of Success
- Command output visible in response
- Time delay confirms blind injection
- DNS/HTTP callback received
- File created/modified on server
- System information extracted""",

    "request_smuggling": """### Indicators of Success
- Request desync between front/back-end
- Subsequent request poisoned
- Other user's request captured
- Cache poisoned via smuggling
- Access controls bypassed""",

    "request-smuggling": """### Indicators of Success
- Request desync between front/back-end
- Subsequent request affected by smuggled content
- Other user's request captured
- Cache poisoned via smuggling
- Access controls bypassed""",

    "cache_poisoning": """### Indicators of Success
- Unkeyed input reflected in cached response
- X-Cache: hit with poisoned content
- Victim receives attacker-controlled response
- XSS executes via cached response
- Cache key manipulation successful""",

    "web-cache-poisoning": """### Indicators of Success
- Unkeyed header/parameter reflected in response
- X-Cache: hit confirms caching
- Clean URL serves poisoned content
- JavaScript executes for victims
- Cache key excludes attacker input""",

    "web-cache-deception": """### Indicators of Success
- Dynamic content cached with static extension
- Sensitive data in cached response
- Victim's session data exposed
- Cache stores personalized content
- Path confusion exploited""",

    "jwt": """### Indicators of Success
- JWT accepted with modified claims
- Algorithm confusion attack works
- Signature verification bypassed
- User context changed via JWT manipulation
- Admin access achieved with forged token""",

    "cors": """### Indicators of Success
- Access-Control-Allow-Origin reflects attacker origin
- Access-Control-Allow-Credentials: true
- Sensitive data readable cross-origin
- Null origin trusted
- Preflight bypass successful""",

    "host_header": """### Indicators of Success
- Host header reflected in response
- Password reset link poisoned
- Internal services accessed via Host manipulation
- Cache poisoned via Host header
- Routing changed to attacker server""",

    "host-header": """### Indicators of Success
- Host header reflected in response/emails
- Password reset link points to attacker server
- SSRF via Host header routing
- Cache poisoned with malicious Host
- Connection state attack successful""",

    "oauth": """### Indicators of Success
- OAuth token stolen via redirect manipulation
- Account linked to attacker's OAuth
- Authorization code intercepted
- Token leakage via referrer
- CSRF in OAuth flow exploited""",

    "nosql": """### Indicators of Success
- NoSQL operator injection works ($ne, $regex)
- Boolean conditions change response
- Data extracted via injection
- Authentication bypassed
- Query logic manipulated""",

    "nosql-injection": """### Indicators of Success
- NoSQL operator injection works
- Boolean responses differ based on condition
- Data extracted character by character
- Authentication bypassed with operator injection
- MongoDB/NoSQL syntax confirmed""",

    "graphql": """### Indicators of Success
- Introspection query returns schema
- Hidden fields/queries discovered
- Authorization bypass via GraphQL
- Batching bypasses rate limits
- Sensitive data exposed via queries""",

    "prototype-pollution": """### Indicators of Success
- __proto__ or constructor.prototype modified
- Pollution affects application behavior
- XSS triggered via polluted property
- Server-side pollution causes RCE
- Gadget chain executes""",

    "race-conditions": """### Indicators of Success
- Concurrent requests bypass limits
- Double-spend or duplicate action
- TOCTOU vulnerability exploited
- Rate limiting circumvented
- Business logic violated via timing""",

    "websockets": """### Indicators of Success
- WebSocket messages manipulated
- XSS via WebSocket message injection
- Authentication bypass on WebSocket
- CSWSH (Cross-Site WebSocket Hijacking)
- Message integrity violated""",

    "clickjacking": """### Indicators of Success
- Target page frameable (no X-Frame-Options)
- Victim clicks hidden element
- Action performed via UI redressing
- Frame buster bypassed
- CSP frame-ancestors missing""",

    "information-disclosure": """### Indicators of Success
- Sensitive data exposed in response
- Error messages reveal internal info
- Debug/trace endpoints accessible
- Source code or credentials leaked
- Version information disclosed""",

    "logic-flaws": """### Indicators of Success
- Business logic bypassed
- Workflow steps skipped
- Price manipulation successful
- Negative values accepted
- State machine violated""",

    "dom-based": """### Indicators of Success
- DOM sink receives tainted source
- JavaScript executes client-side
- URL fragment/hash exploited
- postMessage handling vulnerable
- Client-side redirect manipulated""",

    "api-testing": """### Indicators of Success
- Hidden API endpoints discovered
- Parameter pollution successful
- Mass assignment exploited
- API documentation exposed
- Authorization bypass via API""",

    "llm-attacks": """### Indicators of Success
- Prompt injection executed
- LLM performs unintended action
- Training data extracted
- Content filter bypassed
- Indirect injection via external content""",

    "essential-skills": """### Indicators of Success
- Vulnerability discovered within time limit
- Target file contents retrieved
- Automated scanning identified issue
- Manual testing confirmed vulnerability
- Exploitation successful""",

    "xss_dom": """### Indicators of Success
- DOM sink receives tainted source data
- JavaScript executes via DOM manipulation
- URL fragment or hash value exploited
- postMessage handler vulnerable
- Client-side code processes attacker input""",

    "info_disclosure": """### Indicators of Success
- Sensitive data exposed in response
- Error messages reveal internal details
- Debug endpoints accessible
- Source code or credentials leaked
- Stack traces or version info visible""",

    "llm_attack": """### Indicators of Success
- Prompt injection payload executed
- LLM performs unintended action
- System prompt or training data leaked
- Content filter or guardrails bypassed
- Indirect injection via external content""",

    "logic_flaw": """### Indicators of Success
- Business logic bypassed or manipulated
- Workflow steps skipped or reordered
- Price/quantity manipulation successful
- Negative or extreme values accepted
- State machine or validation violated""",

    "rce": """### Indicators of Success
- Command output visible in response
- Time delay confirms blind execution
- DNS/HTTP callback received at external server
- File created, modified, or deleted
- System information extracted (whoami, id)""",

    "race_condition": """### Indicators of Success
- Concurrent requests bypass rate limits
- Duplicate transactions or actions occur
- TOCTOU (time-of-check-time-of-use) exploited
- Business constraints violated via timing
- Resource limits exceeded through parallelism""",

    "cache_deception": """### Indicators of Success
- Dynamic content cached with static extension
- Sensitive user data in cached response
- Victim's personalized content exposed
- Path confusion leads to caching
- Authentication data leaked via cache""",

    "authentication": """### Indicators of Success
- Login bypassed or credentials extracted
- 2FA or MFA circumvented
- Session hijacked or fixated
- Password reset flow exploited
- Brute force protection bypassed""",
}

def get_indicators(category: str) -> str:
    """Get indicators for a category, with fallback."""
    # Direct match
    if category in INDICATORS:
        return INDICATORS[category]
    
    # Try lowercase
    cat_lower = category.lower()
    if cat_lower in INDICATORS:
        return INDICATORS[cat_lower]
    
    # Try with underscores/hyphens swapped
    cat_underscore = cat_lower.replace("-", "_")
    cat_hyphen = cat_lower.replace("_", "-")
    
    if cat_underscore in INDICATORS:
        return INDICATORS[cat_underscore]
    if cat_hyphen in INDICATORS:
        return INDICATORS[cat_hyphen]
    
    # Partial match
    for key in INDICATORS:
        if key in cat_lower or cat_lower in key:
            return INDICATORS[key]
    
    return None

def fix_playbook(filepath: Path) -> bool:
    """Fix indicators in a single playbook file."""
    content = filepath.read_text()
    
    # Extract category
    cat_match = re.search(r'\*\*Category:\*\*\s*(\S+)', content)
    if not cat_match:
        return False
    
    category = cat_match.group(1)
    
    # Get specific indicators
    new_indicators = get_indicators(category)
    if not new_indicators:
        print(f"  No indicators for category: {category}")
        return False
    
    # Check if indicators are generic
    if "Check for changes in application behavior" not in content:
        return False  # Already has custom indicators
    
    # Replace generic indicators
    pattern = r'### Indicators of Success\n.*?(?=\n---|\n\*Source:|\Z)'
    new_content = re.sub(pattern, new_indicators, content, flags=re.DOTALL)
    
    if new_content != content:
        filepath.write_text(new_content)
        return True
    
    return False

def main():
    labs_dir = Path("/root/resurface/src/prompts/playbooks/labs")
    
    fixed = 0
    skipped = 0
    no_match = 0
    
    for md_file in sorted(labs_dir.glob("*.md")):
        if md_file.name == "INDEX.md":
            continue
        
        result = fix_playbook(md_file)
        if result:
            fixed += 1
            print(f"✓ Fixed: {md_file.name}")
        elif "Check for changes in application behavior" in md_file.read_text():
            no_match += 1
            print(f"✗ No indicators match: {md_file.name}")
        else:
            skipped += 1
    
    print(f"\n{'='*50}")
    print(f"Fixed: {fixed}")
    print(f"Already good: {skipped}")
    print(f"No category match: {no_match}")

if __name__ == "__main__":
    main()
