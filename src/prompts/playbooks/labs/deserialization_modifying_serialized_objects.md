## Modifying serialized objects

**Category:** deserialization
**Difficulty:** Unknown

### Description
This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the usercarlos.

### Solution Steps
1. Log in using your own credentials. Notice that the post-login GET /my-account request contains a session cookie that appears to be URL and Base64-encoded.
2. Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The admin attribute contains b:0 , indicating the boolean value false . Send this request to Burp Repeater.
3. In Burp Repeater, use the Inspector to examine the cookie again and change the value of the admin attribute to b:1 . Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
4. Send the request. Notice that the response now contains a link to the admin panel at /admin , indicating that you have accessed the page with admin privileges.
5. Change the path of your request to /admin and resend it. Notice that the /admin page contains links to delete specific user accounts.
6. Change the path of your request to /admin/delete?username=carlos and send the request to solve the lab.

### Key Payloads
- `carlos`
- `wiener:peter`
- `GET /my-account`
- `admin`
- `false`
- `/admin`
- `/admin/delete?username=carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: deserialization

---
*Source: PortSwigger Web Security Academy*
