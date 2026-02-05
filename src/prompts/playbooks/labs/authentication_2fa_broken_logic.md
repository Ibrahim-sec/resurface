## 2FA broken logic

**Category:** auth_bypass
**Difficulty:** Unknown

### Description
This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

### Solution Steps
Carlos will not attempt to log in to the website himself.

### Key Payloads
- `wiener:peter`
- `carlos`
- `POST /login2`
- `verify`
- `GET /login2`
- `mfa-code`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: auth_bypass

---
*Source: PortSwigger Web Security Academy*
