## Detecting NoSQL injection

**Category:** nosql
**Difficulty:** Unknown

### Description
The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

### Solution Steps
1. In Burp's browser, access the lab and click on a product category filter.
2. In Burp, go to Proxy > HTTP history . Right-click the category filter request and select Send to Repeater .
3. In Repeater, submit a ' character in the category parameter. Notice that this causes a JavaScript syntax error. This may indicate that the user input was not filtered or sanitized correctly.
4. Submit a valid JavaScript payload in the value of the category query parameter. You could use the following payload: Gifts'+' Make sure to URL-encode the payload by highlighting it and using the Ctrl-U hotkey. Notice that it doesn't cause a syntax error. This indicates that a form of server-side injection may be occurring.
5. Identify whether you can inject boolean conditions to change the response: Insert a false condition in the category parameter. For example: Gifts' && 0 && 'x Make sure to URL-encode the payload. Notice that no products are retrieved. Insert a true condition in the category parameter. For example: Gifts' && 1 && 'x Make sure to URL-encode the payload. Notice that products in the Gifts category are retrieved.
6. Submit a boolean condition that always evaluates to true in the category parameter. For example: Gifts'||1||'
7. Right-click the response and select Show response in browser .
8. Copy the URL and load it in Burp's browser. Verify that the response now contains unreleased products. The lab is solved.

### Key Payloads
- `Gifts'+'`
- `Ctrl-U`
- `Gifts' && 0 && 'x`
- `Gifts' && 1 && 'x`
- `Gifts'||1||'`

### Indicators of Success
- NoSQL operator injection works ($ne, $regex)
- Boolean conditions change response
- Data extracted via injection
- Authentication bypassed
- Query logic manipulated
---
*Source: PortSwigger Web Security Academy*
