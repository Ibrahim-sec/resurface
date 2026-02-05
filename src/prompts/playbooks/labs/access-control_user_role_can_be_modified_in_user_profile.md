## User role can be modified in user profile

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has an admin panel at/admin. It's only accessible to logged-in users with aroleidof 2.

### Solution Steps
1. Log in using the supplied credentials and access your account page.
2. Use the provided feature to update the email address associated with your account.
3. Observe that the response contains your role ID.
4. Send the email submission request to Burp Repeater, add "roleid":2 into the JSON in the request body, and resend it.
5. Observe that the response shows your roleid has changed to 2.
6. Browse to /admin and delete carlos .

### Key Payloads
- `/admin`
- `roleid`
- `carlos`
- `wiener:peter`
- `"roleid":2`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
