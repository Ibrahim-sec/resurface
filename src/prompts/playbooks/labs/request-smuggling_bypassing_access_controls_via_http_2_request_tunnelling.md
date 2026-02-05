## Bypassing access controls via HTTP/2 request tunnelling

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming header names. To solve the lab, access the admin panel at/adminas theadministratoruser and delete the usercarlos.

### Solution Steps
The front-end server appends a series of
client authentication headers
to incoming requests. You need to find a way of leaking these.

### Key Payloads
- `/admin`
- `administrator`
- `carlos`
- `GET /`
- `Host`
- `foo: bar\r\nHost: abc`
- `GET /?search=YOUR-SEARCH-QUERY`
- `search`
- `POST`
- `Content-Length`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: request_smuggling

---
*Source: PortSwigger Web Security Academy*
