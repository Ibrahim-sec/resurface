## SSRF via flawed request parsing

**Category:** host_header
**Difficulty:** Unknown

### Description
This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address.

### Solution Steps
1. Send the GET / request that received a 200 response to Burp Repeater and study the lab's behavior. Observe that the website validates the Host header and blocks any requests in which it has been modified.
2. Observe that you can also access the home page by supplying an absolute URL in the request line as follows: GET https://YOUR-LAB-ID.web-security-academy.net/
3. Notice that when you do this, modifying the Host header no longer causes your request to be blocked. Instead, you receive a timeout error. This suggests that the absolute URL is being validated instead of the Host header.
4. Use Burp Collaborator to confirm that you can make the website's middleware issue requests to an arbitrary server in this way. For example, the following request will trigger an HTTP request to your Collaborator server: GET https://YOUR-LAB-ID.web-security-academy.net/
Host: BURP-COLLABORATOR-SUBDOMAIN
5. Right-click and select Insert Collaborator payload to insert a Burp Collaborator subdomain where indicated in the request.
6. Send the request containing the absolute URL to Burp Intruder.
7. Go to Intruder and deselect Update Host header to match target .
8. Use the Host header to scan the IP range 192.168.0.0/24 to identify the IP address of the admin interface. Send this request to Burp Repeater.
9. In Burp Repeater, append /admin to the absolute URL in the request line and send the request. Observe that you now have access to the admin panel, including a form for deleting users.
10. Change the absolute URL in your request to point to /admin/delete . Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a username parameter containing carlos . The request line should now look like this but with a different CSRF token: GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos
11. Copy the session cookie from the Set-Cookie header in the displayed response and add it to your request.
12. Right-click on your request and select "Change request method". Burp will convert it to a POST request.
13. Send the request to delete carlos and solve the lab.

### Key Payloads
- `192.168.0.0/24`
- `carlos`
- `GET /`
- `GET https://YOUR-LAB-ID.web-security-academy.net/`
- `GET https://YOUR-LAB-ID.web-security-academy.net/
Host: BURP-COLLABORATOR-SUBDOMAIN`
- `/admin`
- `/admin/delete`
- `username`
- `GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos`
- `Set-Cookie`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: host_header

---
*Source: PortSwigger Web Security Academy*
