## Web cache poisoning via an unkeyed query parameter

**Category:** cache_poisoning
**Difficulty:** Medium

### Description
This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. A user regularly visits this site's home page using Chrome.

### Solution Steps
1. Analyze the homepage and identify how content is cached
2. Test for parameters excluded from cache key - try utm_ parameters
3. Send request with: `GET /?utm_content=test123`
4. Check response headers for caching (X-Cache: hit/miss)
5. The utm_content parameter is excluded from the cache key
6. Test if the parameter value is reflected anywhere in the response
7. If reflected in HTML context, inject XSS payload:
8. `GET /?utm_content='/><script>alert(1)</script>`
9. Send request repeatedly until cache stores the poisoned response
10. When victim visits the homepage (no parameters), they get the cached poisoned response
11. The XSS payload executes in their browser

### Key Payloads
- `alert(1)`
- `utm_content`
- `GET /?utm_content='/><script>alert(1)</script>`
- `X-Cache: hit`
- `X-Cache: miss`

### Indicators of Success
- utm_content excluded from cache key (verify with X-Cache-Key header if present)
- Parameter value reflected in response HTML
- Response cached with X-Cache: hit
- Clean URL (/) serves poisoned response
- XSS executes for victim users

---
*Source: PortSwigger Web Security Academy*
