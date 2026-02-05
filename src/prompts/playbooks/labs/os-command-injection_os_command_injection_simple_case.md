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
- Command output visible in response
- Time delay confirms blind execution
- DNS/HTTP callback received at external server
- File created, modified, or deleted
- System information extracted (whoami, id)
---
*Source: PortSwigger Web Security Academy*
