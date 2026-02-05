## Host validation bypass via connection state attack

**Category:** host_header
**Difficulty:** Unknown

### Description
This lab is vulnerable to routing-based SSRF via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.

### Solution Steps
Solving this lab requires features first released in
Burp Suite 2022.8.1
.

### Key Payloads
- `192.168.0.1/admin`
- `carlos`
- `GET /`
- `/admin`
- `Host`
- `192.168.0.1`
- `YOUR-LAB-ID.h1-web-security-academy.net`
- `Connection`
- `keep-alive`
- `/admin/delete`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: host_header

---
*Source: PortSwigger Web Security Academy*
