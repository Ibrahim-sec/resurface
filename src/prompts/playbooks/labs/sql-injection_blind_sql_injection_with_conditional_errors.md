## Blind SQL injection with conditional errors

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

### Solution Steps
This lab uses an Oracle database. For more information, see the
SQL injection cheat sheet
.

### Key Payloads
- `users`
- `username`
- `password`
- `administrator`
- `TrackingId`
- `TrackingId=xyz`
- `TrackingId=xyz'`
- `TrackingId=xyz''`
- `TrackingId=xyz'||(SELECT '')||'`
- `TrackingId=xyz'||(SELECT '' FROM dual)||'`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
