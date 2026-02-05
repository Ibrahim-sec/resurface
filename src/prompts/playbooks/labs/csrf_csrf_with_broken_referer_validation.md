## CSRF with broken Referer validation

**Category:** csrf
**Difficulty:** Unknown

### Description
This lab's email change functionality is vulnerable to CSRF. It attempts to detect and block cross domain requests, but the detection mechanism can be bypassed.

### Solution Steps
You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

### Key Payloads
- `wiener:peter`
- `Referer: https://arbitrary-incorrect-domain.net?YOUR-LAB-ID.web-security-academy.net`
- `history.pushState()`
- `history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net")`
- `Referrer-Policy: unsafe-url`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: csrf

---
*Source: PortSwigger Web Security Academy*
