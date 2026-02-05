## 0.CL request smuggling

**Category:** request_smuggling
**Difficulty:** Expert

### Description
This lab is vulnerable to request smuggling because the front-end server ignores the Content-Length header on requests that have a Transfer-Encoding header. The goal is to execute alert() in another user's browser who visits the homepage.

### Solution Steps
1. Identify the smuggling variant - front-end uses Transfer-Encoding, back-end uses Content-Length
2. The front-end treats Content-Length: 0 specially when Transfer-Encoding is present
3. Craft a smuggling request that injects a malicious prefix into the next user's request
4. The smuggled portion should contain an XSS payload that will be reflected
5. Structure the request with Transfer-Encoding: chunked and Content-Length: 0
6. The body after the "0\r\n\r\n" terminator becomes smuggled to the next request
7. Inject HTML/JS payload: `<script>alert()</script>` in a way it reflects in response
8. Send the poisoned request repeatedly until a victim's request is affected
9. When the victim visits, their request gets prefixed with your XSS payload
10. The server responds with the reflected XSS, executing alert() in their browser

### Key Payloads
- `alert()`
- `Transfer-Encoding: chunked`
- `Content-Length: 0`
- `0\r\n\r\n`
- `<script>alert(1)</script>`
- `GET / HTTP/1.1`

### Indicators of Success
- Smuggled request affects subsequent requests
- XSS payload reflects in victim's response
- alert() executes in victim's browser
- Timing indicates request desync between front/back-end

---
*Source: PortSwigger Web Security Academy*
