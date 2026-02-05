## PATH TRAVERSAL Playbook
*Synthesized from 6 PortSwigger labs*

### Overview
This playbook covers 6 known attack techniques for path_traversal.

### Attack Techniques

**Bypass Techniques:**
- File path traversal, traversal sequences blocked with absolute path bypass
- File path traversal, validation of file extension with null byte bypass

**General:**
- File path traversal, traversal sequences stripped non-recursively
- File path traversal, simple case
- File path traversal, traversal sequences stripped with superfluous URL-decode
- File path traversal, validation of start of path

### Key Payloads
```
....//....//....//etc/passwd
/var/www/images/../../../etc/passwd
/etc/passwd
../../../etc/passwd
..%252f..%252f..%252fetc/passwd
../../../etc/passwd%00.png
filename
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

