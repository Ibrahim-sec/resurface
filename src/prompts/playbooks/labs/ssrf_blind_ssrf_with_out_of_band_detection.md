## Blind SSRF with out-of-band detection

**Category:** ssrf
**Difficulty:** Unknown

### Description
This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.

### Solution Steps
1. Visit a product, intercept the request in Burp Suite, and send it to Burp Repeater.
2. Go to the Repeater tab. Select the Referer header, right-click and select "Insert Collaborator Payload" to replace the original domain with a Burp Collaborator generated domain. Send the request.
3. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
4. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

### Indicators of Success
- Internal IP/port responds through application
- Cloud metadata endpoint accessed (169.254.169.254)
- DNS lookup to attacker server received
- Internal services enumerated
- Localhost/127.0.0.1 accessible
---
*Source: PortSwigger Web Security Academy*
