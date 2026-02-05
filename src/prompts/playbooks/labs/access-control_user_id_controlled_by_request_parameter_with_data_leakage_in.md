## User ID controlled by request parameter with data leakage in redirect

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

### Solution Steps
1. Log in using the supplied credentials and access your account page.
2. Send the request to Burp Repeater.
3. Change the "id" parameter to carlos .
4. Observe that although the response is now redirecting you to the home page, it has a body containing the API key belonging to carlos .
5. Submit the API key.

### Key Payloads
- `carlos`
- `wiener:peter`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
