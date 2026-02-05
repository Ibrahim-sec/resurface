## CSRF where token is not tied to user session

**Category:** csrf
**Difficulty:** Unknown

### Description
This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't integrated into the site's session handling system.

### Solution Steps
You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

### Key Payloads
- `wiener:peter`
- `carlos:montoya`

### Indicators of Success
- State-changing action performed without user consent
- No CSRF token required or token bypassable
- Forged request accepted by server
- Victim's account modified via attacker page
- SameSite cookie restrictions bypassed
---
*Source: PortSwigger Web Security Academy*
