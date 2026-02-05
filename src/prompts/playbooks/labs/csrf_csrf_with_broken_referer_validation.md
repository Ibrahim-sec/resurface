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
- State-changing action performed without user consent
- No CSRF token required or token bypassable
- Forged request accepted by server
- Victim's account modified via attacker page
- SameSite cookie restrictions bypassed
---
*Source: PortSwigger Web Security Academy*
