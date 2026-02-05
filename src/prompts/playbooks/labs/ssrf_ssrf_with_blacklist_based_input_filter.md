## SSRF with blacklist-based input filter

**Category:** ssrf
**Difficulty:** Unknown

### Description
This lab has a stock check feature which fetches data from an internal system.

### Solution Steps
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the stockApi parameter to http://127.0.0.1/ and observe that the request is blocked.
3. Bypass the block by changing the URL to: http://127.1/
4. Change the URL to http://127.1/admin and observe that the URL is blocked again.
5. Obfuscate the "a" by double-URL encoding it to %2561 to access the admin interface and delete the target user.

### Key Payloads
- `http://localhost/admin`
- `carlos`
- `stockApi`
- `http://127.0.0.1/`
- `http://127.1/`
- `http://127.1/admin`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: ssrf

---
*Source: PortSwigger Web Security Academy*
