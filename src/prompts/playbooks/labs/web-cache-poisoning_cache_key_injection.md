## Cache key injection

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab contains multiple independent vulnerabilities, including cache key injection. A user regularly visits this site's home page using Chrome.

### Solution Steps
Solving this lab requires an understanding of several other web vulnerabilities. If you're still having trouble solving it after several hours, we recommend completing all other topics on the
Web Security Academy
first.

### Key Payloads
- `alert(1)`
- `Pragma: x-get-cache-key`
- `/login`
- `utm_content`
- `lang`
- `/login?lang=en?utm_content=anything`
- `/login/`
- `/js/localize.js`
- `Origin`
- `cors`

### Indicators of Success
- Unkeyed input reflected in cached response
- X-Cache: hit with poisoned content
- Victim receives attacker-controlled response
- XSS executes via cached response
- Cache key manipulation successful
---
*Source: PortSwigger Web Security Academy*
