## CACHE POISONING Playbook
*Synthesized from 13 PortSwigger labs*

### Overview
This playbook covers 13 known attack techniques for cache_poisoning.

### Attack Techniques

**DOM-based:**
- Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria

**General:**
- Combining web cache poisoning vulnerabilities
- Targeted web cache poisoning using an unknown header
- Web cache poisoning with an unkeyed cookie
- Web cache poisoning with an unkeyed header
- Web cache poisoning with multiple headers
- Cache key injection
- Web cache poisoning via a fat GET request
- Internal cache poisoning

### Key Payloads
```
cors
User-Agent
https://example.com/
/js/localize.js
{
"country": "<img src=1 onerror=alert(document.cookie) />"
}
callback
analytics.js
lang
/resources/js/geolocate.js
fehost
GET /?utm_content='/><script>alert(1)</script>
alert()
/login?lang=en?utm_content=anything
initGeoLocate()
alert(document.cookie)
GET /random
X-Original-URL
data.host
GET /?evil='/><script>alert(1)</script>
alert(1)
```

### Bypass Techniques
- 2. Observe that any changes to the query string are always reflected in the response. This indicates that the external cache includes this in the cach

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

