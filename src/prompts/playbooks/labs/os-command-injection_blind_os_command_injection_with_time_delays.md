## Blind OS command injection with time delays

**Category:** rce
**Difficulty:** Unknown

### Description
This lab contains a blind OS command injection vulnerability in the feedback function.

### Solution Steps
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the email parameter, changing it to: email=x||ping+-c+10+127.0.0.1||
3. Observe that the response takes 10 seconds to return.

### Key Payloads
- `email`
- `email=x||ping+-c+10+127.0.0.1||`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: rce

---
*Source: PortSwigger Web Security Academy*
