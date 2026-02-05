## Unprotected admin functionality with unpredictable URL

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

### Solution Steps
1. Review the lab home page's source using Burp Suite or your web browser's developer tools.
2. Observe that it contains some JavaScript that discloses the URL of the admin panel.
3. Load the admin panel and delete carlos .

### Key Payloads
- `carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
