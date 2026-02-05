## BROKEN ACCESS CONTROL Playbook
*Synthesized from 13 PortSwigger labs*

### Overview
This playbook covers 13 known attack techniques for broken_access_control.

### Attack Techniques

**General:**
- Insecure direct object references
- Method-based access control can be circumvented
- Multi-step process with no access control on one step
- Referer-based access control
- Unprotected admin functionality
- Unprotected admin functionality with unpredictable URL
- URL-based access control can be circumvented
- User ID controlled by request parameter

### Key Payloads
```
robots.txt
Disallow
/admin-roles?username=[TARGET_USER]&action=upgrade
/administrator-panel
administrator:admin
/admin
X-Original-URL
roleid
Admin=false
?username=[TARGET_USER]
administrator
Admin=true
"roleid":2
POST
X-Original-URL: /invalid
1.txt
[TEST_USER]:[TEST_PASS]
POSTX
/robots.txt
/admin/delete
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

