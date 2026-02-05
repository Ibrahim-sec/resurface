## 2FA bypass using a brute-force attack

**Category:** auth_bypass
**Difficulty:** Unknown

### Description
This lab's two-factor authentication is vulnerable to brute-forcing. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, brute-force the 2FA code and access Carlos's account page.

### Solution Steps
You will need to use Burp macros in conjunction with Burp Intruder to solve this lab. For more information about macros, please refer to the
Burp Suite documentation
. Users proficient in Python might prefer to use the
Turbo Intruder
extension, which is available from the BApp store.

### Key Payloads
- `carlos:montoya`
- `carlos`
- `GET /login
POST /login
GET /login2`
- `POST /login2`
- `mfa-code`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: auth_bypass

---
*Source: PortSwigger Web Security Academy*
