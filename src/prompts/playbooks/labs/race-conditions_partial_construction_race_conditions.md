## Partial construction race conditions

**Category:** race_condition
**Difficulty:** Unknown

### Description
This lab contains a user registration mechanism. A race condition enables you to bypass email verification and register with an arbitrary email address that you do not own.

### Solution Steps
You may need to experiment with different ways of lining up the race window to successfully exploit this vulnerability.

### Key Payloads
- `carlos`
- `@ginandjuice.shop`
- `/resources/static/users.js`
- `POST`
- `/confirm`
- `POST /confirm?token=1 HTTP/2
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: x-www-form-urlencoded
    Content-Length: 0`
- `token`
- `Incorrect token: <YOUR-TOKEN>`
- `Missing parameter: token`
- `Forbidden`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: race_condition

---
*Source: PortSwigger Web Security Academy*
