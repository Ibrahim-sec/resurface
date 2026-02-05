## Server-side pause-based request smuggling

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to pause-based server-side request smuggling. The front-end server streams requests to the back-end, and the back-end server does not close the connection after a timeout on some endpoints.

### Solution Steps
1. In Burp, notice from the Server response header that the lab is using Apache 2.4.52 . This version of Apache is potentially vulnerable to pause-based CL.0 attacks on endpoints that trigger server-level redirects.
2. In Burp Repeater, try issuing a request for a valid directory without including a trailing slash, for example, GET /resources . Observe that you are redirected to /resources/ .
3. Right-click the request and select Extensions > Turbo Intruder > Send to Turbo Intruder .
4. In Turbo Intruder, convert the request to a POST request (right-click and select Change request method ).
5. Change the Connection header to keep-alive .
6. Add a complete GET /admin request to the body of the main request. The result should look something like this: POST /resources HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /admin/ HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
7. In the Python editor panel, enter the following script. This issues the request twice, pausing for 61 seconds after the \r\n\r\n sequence at the end of the headers: def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=500,
                           pipeline=False
                           )

    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
8. Launch the attack. Initially, you won't see anything happening, but after 61 seconds, you should see two entries in the results table: The first entry is the POST /resources request, which triggered a redirect to /resources/ as normal. The second entry is a response to the GET /admin/ request. Although this just tells you that the admin panel is only accessible to local users, this confirms the pause-based CL.0 vulnerability.

### Key Payloads
- `/admin`
- `carlos`
- `Server`
- `Apache 2.4.52`
- `GET /resources`
- `/resources/`
- `POST`
- `Connection`
- `keep-alive`
- `GET /admin`

### Indicators of Success
- Request desync between front/back-end
- Subsequent request poisoned
- Other user's request captured
- Cache poisoned via smuggling
- Access controls bypassed
---
*Source: PortSwigger Web Security Academy*
