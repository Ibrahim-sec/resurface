## Routing-based SSRF

**Category:** host_header
**Difficulty:** Unknown

### Description
This lab is vulnerable to routing-based SSRF via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address.

### Solution Steps
1. Send the GET / request that received a 200 response to Burp Repeater.
2. In Burp Repeater, select the Host header value, right-click and select Insert Collaborator payload to replace it with a Collaborator domain name. Send the request.
3. Go to the Collaborator tab and click Poll now . You should see a couple of network interactions in the table, including an HTTP request. This confirms that you are able to make the website's middleware issue requests to an arbitrary server.
4. Send the GET / request to Burp Intruder.
5. Go to Intruder .
6. Deselect Update Host header to match target .
7. Delete the value of the Host header and replace it with the following IP address, adding a payload position to the final octet: Host: 192.168.0.§0§
8. In the Payloads side panel, select the payload type Numbers . Under Payload configuration , enter the following values: From: 0
To: 255
Step: 1
9. Click Start attack . A warning will inform you that the Host header does not match the specified target host. As we've done this deliberately, you can ignore this message.
10. When the attack finishes, click the Status column to sort the results. Notice that a single request received a 302 response redirecting you to /admin . Send this request to Burp Repeater.
11. In Burp Repeater, change the request line to GET /admin and send the request. In the response, observe that you have successfully accessed the admin panel.
12. Study the form for deleting users. Notice that it will generate a POST request to /admin/delete with both a CSRF token and username parameter. You need to manually craft an equivalent request to delete carlos .
13. Change the path in your request to /admin/delete . Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a username parameter containing carlos . The request line should now look like this but with a different CSRF token: GET /admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos
14. Copy the session cookie from the Set-Cookie header in the displayed response and add it to your request.
15. Right-click on your request and select Change request method . Burp will convert it to a POST request.
16. Send the request to delete carlos and solve the lab.

### Key Payloads
- `192.168.0.0/24`
- `carlos`
- `GET /`
- `Host: 192.168.0.§0§`
- `From: 0
To: 255
Step: 1`
- `/admin`
- `GET /admin`
- `POST`
- `/admin/delete`
- `username`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: host_header

---
*Source: PortSwigger Web Security Academy*
