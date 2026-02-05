## Broken brute-force protection, IP block

**Category:** auth_bypass
**Difficulty:** Unknown

### Description
This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

### Solution Steps
Advanced users may want to solve this lab by using a macro or the Turbo Intruder extension. However, it is possible to solve the lab without using these advanced features.

### Key Payloads
- `wiener:peter`
- `carlos`
- `POST /login`
- `username`
- `password`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: auth_bypass

---
*Source: PortSwigger Web Security Academy*
