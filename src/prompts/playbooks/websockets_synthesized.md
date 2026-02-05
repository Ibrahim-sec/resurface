## WEBSOCKETS Playbook
*Synthesized from 2 PortSwigger labs*

### Overview
This playbook covers 2 known attack techniques for websockets.

### Attack Techniques

**General:**
- Manipulating the WebSocket handshake to exploit vulnerabilities
- Manipulating WebSocket messages to exploit vulnerabilities

### Key Payloads
```
<img src=1 onerror='alert(1)'>
<img src=1 oNeRrOr=alert`1`>
X-Forwarded-For: 1.1.1.1
X-Forwarded-For
alert()
```

### Bypass Techniques
- If you're struggling to bypass the XSS filter, try out our
- Sometimes you can bypass IP-based restrictions using HTTP headers like

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

