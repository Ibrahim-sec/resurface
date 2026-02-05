## SQL injection UNION attack, determining the number of columns returned by the query

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

### Solution Steps
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Modify the category parameter, giving it the value '+UNION+SELECT+NULL-- . Observe that an error occurs.
3. Modify the category parameter to add an additional column containing a null value: '+UNION+SELECT+NULL,NULL--
4. Continue adding null values until the error disappears and the response includes additional content containing the null values.

### Key Payloads
- `category`
- `'+UNION+SELECT+NULL--`
- `'+UNION+SELECT+NULL,NULL--`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
