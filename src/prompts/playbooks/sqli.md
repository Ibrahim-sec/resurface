## SQL Injection Playbook

**STRATEGY:** Test login and search forms for SQL injection.

### Steps
1. Find the login form
2. Type in email/username field: `' OR 1=1--`
3. Type any password and press Enter
4. If you get logged in → CONFIRMED (auth bypass)
5. Also try search fields with: `' UNION SELECT NULL--`
6. Check for database errors or unexpected data in responses

### Indicators of Success
- Login succeeds with SQLi payload (authentication bypass)
- Database error messages exposed
- UNION-based data extraction works
- Time-based delays confirm blind SQLi

### Common Payloads
- Auth bypass: `' OR 1=1--`, `admin'--`, `' OR '1'='1`
- Error-based: `'`, `''`, `\`
- UNION: `' UNION SELECT NULL--`
- Time-based: `'; WAITFOR DELAY '0:0:5'--`
