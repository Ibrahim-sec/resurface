## User ID controlled by request parameter with password disclosure

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has user account page that contains the current user's existing password, prefilled in a masked input.

### Solution Steps
1. Log in using the supplied credentials and access the user account page.
2. Change the "id" parameter in the URL to administrator .
3. View the response in Burp and observe that it contains the administrator's password.
4. Log in to the administrator account and delete carlos .

### Key Payloads
- `carlos`
- `wiener:peter`
- `administrator`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
