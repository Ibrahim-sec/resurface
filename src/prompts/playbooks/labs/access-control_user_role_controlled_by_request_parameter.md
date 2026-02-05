## User role controlled by request parameter

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has an admin panel at/admin, which identifies administrators using a forgeable cookie.

### Solution Steps
1. Browse to /admin and observe that you can't access the admin panel.
2. Browse to the login page.
3. In Burp Proxy, turn interception on and enable response interception.
4. Complete and submit the login page, and forward the resulting request in Burp.
5. Observe that the response sets the cookie Admin=false . Change it to Admin=true .
6. Load the admin panel and delete carlos .

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `Admin=false`
- `Admin=true`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
