## CORS Playbook
*Synthesized from 3 PortSwigger labs*

### Overview
This playbook covers 3 known attack techniques for cors.

### Attack Techniques

**General:**
- CORS vulnerability with basic origin reflection
- CORS vulnerability with trusted insecure protocols
- CORS vulnerability with trusted null origin

### Key Payloads
```
lab-id
[EXPLOIT_SERVER]-ID
Origin: https://example.com
Origin: http://subdomain.lab-id
[TEST_USER]:[TEST_PASS]
Origin: null.
Access-Control-Allow-Credentials
productID
Access-Control-Allow-Origin
/accountDetails
[LAB_ID]
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

