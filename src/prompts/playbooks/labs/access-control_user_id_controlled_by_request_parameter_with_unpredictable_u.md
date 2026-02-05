## User ID controlled by request parameter, with unpredictable user IDs

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

### Solution Steps
1. Find a blog post by carlos .
2. Click on carlos and observe that the URL contains his user ID. Make a note of this ID.
3. Log in using the supplied credentials and access your account page.
4. Change the "id" parameter to the saved user ID.
5. Retrieve and submit the API key.

### Key Payloads
- `carlos`
- `wiener:peter`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
