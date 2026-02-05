## User ID controlled by request parameter

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has a horizontal privilege escalation vulnerability on the user account page.

### Solution Steps
1. Log in using the supplied credentials and go to your account page.
2. Note that the URL contains your username in the "id" parameter.
3. Send the request to Burp Repeater.
4. Change the "id" parameter to carlos .
5. Retrieve and submit the API key for carlos .

### Key Payloads
- `carlos`
- `wiener:peter`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
