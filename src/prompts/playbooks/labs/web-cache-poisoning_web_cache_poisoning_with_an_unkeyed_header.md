## Web cache poisoning with an unkeyed header

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executesalert(document.cookie)in the visitor's browser.

### Solution Steps
This lab supports the
X-Forwarded-Host
header.

### Key Payloads
- `alert(document.cookie)`
- `X-Forwarded-Host`
- `?cb=1234`
- `example.com`
- `/resources/js/tracking.js`
- `X-Cache: hit`
- `X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
- `alert()`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: cache_poisoning

---
*Source: PortSwigger Web Security Academy*
