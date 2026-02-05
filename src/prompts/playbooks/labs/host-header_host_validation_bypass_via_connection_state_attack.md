## Host validation bypass via connection state attack

**Category:** host_header
**Difficulty:** Expert

### Description
This lab is vulnerable to routing-based SSRF via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.

### Solution Steps
1. Identify that the Host header is validated on the first request of a connection
2. The front-end validates Host only on the initial request, then trusts subsequent requests on the same connection
3. Use HTTP/1.1 connection reuse (keep-alive) to exploit this
4. First, send a legitimate request with valid Host header and Connection: keep-alive
5. On the SAME TCP connection, send a second request with malicious Host: 192.168.0.1
6. The front-end won't re-validate the Host on subsequent requests
7. The malicious Host routes to internal admin panel at 192.168.0.1/admin
8. Enumerate internal endpoints and find admin functionality
9. Use the admin panel to delete carlos: /admin/delete?username=carlos
10. Continue exploiting internal services via Host header manipulation on reused connections

### Key Payloads
- `192.168.0.1/admin`
- `carlos`
- `GET /`
- `/admin`
- `Host: 192.168.0.1`
- `Host: YOUR-LAB-ID.web-security-academy.net`
- `Connection: keep-alive`
- `/admin/delete?username=carlos`

### Indicators of Success
- First request succeeds with valid Host
- Second request on same connection routes to internal IP
- Admin panel accessible via manipulated Host
- Internal resources respond on reused connection

---
*Source: PortSwigger Web Security Academy*
