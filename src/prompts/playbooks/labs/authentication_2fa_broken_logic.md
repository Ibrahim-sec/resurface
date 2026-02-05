## 2FA broken logic

**Category:** auth_bypass
**Difficulty:** Medium

### Description
This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

### Solution Steps
1. Login with valid credentials (wiener:peter) and complete the 2FA process normally
2. Observe the 2FA verification flow - note the `verify` parameter or cookie that identifies whose 2FA code is being verified
3. After completing 2FA for wiener, intercept a request to the 2FA verification page (GET /login2)
4. Change the `verify` parameter/cookie value from `wiener` to `carlos`
5. Now the server expects Carlos's 2FA code but you control the session
6. Brute-force the MFA code (typically 4-6 digits) by sending POST requests to /login2 with `mfa-code` parameter
7. When the correct code is found, you'll be logged in as Carlos
8. Access Carlos's account page to complete the attack

### Key Payloads
- `wiener:peter`
- `carlos`
- `POST /login2`
- `verify`
- `GET /login2`
- `mfa-code`

### Indicators of Success
- Successfully accessing /my-account as carlos
- HTTP 302 redirect to account page after correct MFA code
- Session cookie changes to carlos's session
- "My Account" page shows carlos's details

---
*Source: PortSwigger Web Security Academy*
