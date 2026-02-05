## Method-based access control can be circumvented

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentialsadministrator:admin.

### Solution Steps
1. Log in using the admin credentials.
2. Browse to the admin panel, promote carlos , and send the HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Attempt to re-promote carlos with the non-admin user by copying that user's session cookie into the existing Burp Repeater request, and observe that the response says "Unauthorized".
5. Change the method from POST to POSTX and observe that the response changes to "missing parameter".
6. Convert the request to use the GET method by right-clicking and selecting "Change request method".
7. Change the username parameter to your username and resend the request.

### Key Payloads
- `administrator:admin`
- `wiener:peter`
- `carlos`
- `POST`
- `POSTX`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
