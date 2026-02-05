## Web cache poisoning with multiple headers

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab contains a web cache poisoning vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executesalert(document.cookie)in the visitor's browser.

### Solution Steps
This lab supports both the
X-Forwarded-Host
and
X-Forwarded-Scheme
headers.

### Key Payloads
- `alert(document.cookie)`
- `X-Forwarded-Host`
- `X-Forwarded-Scheme`
- `/resources/js/tracking.js`
- `example.com`
- `HTTPS`
- `Location`
- `https://`
- `X-Forwarded-Host: example.com`
- `X-Forwarded-Scheme: nothttps`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: cache_poisoning

---
*Source: PortSwigger Web Security Academy*
