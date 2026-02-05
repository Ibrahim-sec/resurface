## Basic SSRF against the local server

**Category:** ssrf
**Difficulty:** Unknown

### Description
This lab has a stock check feature which fetches data from an internal system.

### Solution Steps
1. Browse to /admin and observe that you can't directly access the admin page.
2. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Change the URL in the stockApi parameter to http://localhost/admin . This should display the administration interface.
4. Read the HTML to identify the URL to delete the target user, which is: http://localhost/admin/delete?username=carlos
5. Submit this URL in the stockApi parameter, to deliver the SSRF attack.

### Key Payloads
- `http://localhost/admin`
- `carlos`
- `/admin`
- `stockApi`
- `http://localhost/admin/delete?username=carlos`

### Indicators of Success
- Internal IP/port responds through application
- Cloud metadata endpoint accessed (169.254.169.254)
- DNS lookup to attacker server received
- Internal services enumerated
- Localhost/127.0.0.1 accessible
---
*Source: PortSwigger Web Security Academy*
