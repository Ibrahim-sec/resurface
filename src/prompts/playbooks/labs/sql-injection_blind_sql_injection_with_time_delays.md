## Blind SQL injection with time delays

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

### Solution Steps
You can find some useful payloads on our
SQL injection cheat sheet
.

### Key Payloads
- `TrackingId`
- `TrackingId=x'||pg_sleep(10)--`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
