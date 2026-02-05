## URL normalization

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab contains an XSS vulnerability that is not directly exploitable due to browser URL-encoding.

### Solution Steps
1. In Burp Repeater, browse to any non-existent path, such as GET /random . Notice that the path you requested is reflected in the error message.
2. Add a suitable reflected XSS payload to the request line: GET /random</p><script>alert(1)</script><p>foo
3. Notice that if you request this URL in the browser, the payload doesn't execute because it is URL-encoded.
4. In Burp Repeater, poison the cache with your payload and then immediately load the URL in the browser. This time, the alert() is executed because the browser's encoded payload was URL-decoded by the cache, causing a cache hit with the earlier request.
5. Re-poison the cache then immediately go to the lab and click "Deliver link to victim". Submit your malicious URL. The lab will be solved when the victim visits the link.

### Key Payloads
- `alert(1)`
- `GET /random`
- `GET /random</p><script>alert(1)</script><p>foo`
- `alert()`

### Indicators of Success
- Unkeyed input reflected in cached response
- X-Cache: hit with poisoned content
- Victim receives attacker-controlled response
- XSS executes via cached response
- Cache key manipulation successful
---
*Source: PortSwigger Web Security Academy*
