## RACE CONDITION Playbook
*Synthesized from 6 PortSwigger labs*

### Overview
This playbook covers 6 known attack techniques for race_condition.

### Attack Techniques

**General:**
- Bypassing rate limits via race conditions
- Limit overrun race conditions
- Multi-endpoint race conditions
- Partial construction race conditions
- Single-endpoint race conditions

**Time-based:**
- Exploiting time-sensitive vulnerabilities

### Key Payloads
```
examples/race-single-packet-attack.py
Invalid username and password
productId
anything@exploit-<[EXPLOIT_SERVER]-ID>.exploit-server.net
GET /forgot-password
wordlists.clipboard
GET /cart
POST /cart/checkout
POST /my-account/change-email
email
Forbidden
/confirm
Invalid username or password
Missing parameter: token
@exploit-<[EXPLOIT_SERVER]-ID>.exploit-server.net
/resources/static/users.js
test1@exploit-<[EXPLOIT_SERVER]-ID>.exploit-server.net, test2@..., test3@...
POST /login
token
POST /confirm?token=1 HTTP/2
    Host: [LAB_ID].[TARGET]
    Cookie: phpsessionid=YOUR-SESSION-ID
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0
```

### Bypass Techniques
- 2. Consider that the shopping cart mechanism and, in particular, the restrictions that determine what you are allowed to order, are worth trying to by
- 2. Consider that the shopping cart mechanism and, in particular, the restrictions that determine what you are allowed to order, are worth trying to by

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

