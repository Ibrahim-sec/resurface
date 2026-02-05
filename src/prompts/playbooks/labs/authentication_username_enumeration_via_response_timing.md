## Username enumeration via response timing

**Category:** auth_bypass
**Difficulty:** Unknown

### Description
This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

### Solution Steps
To add to the challenge, the lab also implements a form of IP-based brute-force protection. However, this can be easily bypassed by manipulating HTTP request headers.

### Key Payloads
- `wiener:peter`
- `POST /login`
- `X-Forwarded-For`
- `username`
- `password`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: auth_bypass

---
*Source: PortSwigger Web Security Academy*
