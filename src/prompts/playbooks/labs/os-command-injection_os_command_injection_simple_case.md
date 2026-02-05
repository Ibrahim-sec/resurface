## OS command injection, simple case

**Category:** rce
**Difficulty:** Unknown

### Description
This lab contains an OS command injection vulnerability in the product stock checker.

### Solution Steps
1. Use Burp Suite to intercept and modify a request that checks the stock level.
2. Modify the storeID parameter, giving it the value 1|whoami .
3. Observe that the response contains the name of the current user.

### Key Payloads
- `whoami`
- `storeID`
- `1|whoami`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: rce

---
*Source: PortSwigger Web Security Academy*
