## LOGIC FLAW Playbook
*Synthesized from 12 PortSwigger labs*

### Overview
This playbook covers 12 known attack techniques for logic_flaw.

### Attack Techniques

**Bypass Techniques:**
- Authentication bypass via encryption oracle
- Authentication bypass via flawed state machine

**General:**
- Bypassing access controls using email address parsing discrepancies
- Excessive trust in client-side controls
- Flawed enforcement of business rules
- High-level logic vulnerability
- Inconsistent handling of exceptional input
- Inconsistent security controls
- Infinite money logic flaw
- Insufficient workflow validation

### Key Payloads
```
very-long-string@YOUR-EMAIL-ID.[TARGET]
attacker@[[EXPLOIT_SERVER]-ID] ?=@ginandjuice.shop
anything@your-email-id.[TARGET]
very-long-string
=?utf-8?q?=61=62=63?=foo@ginandjuice.shop
=?iso-8859-1?q?=61=62=63?=foo@ginandjuice.shop
=?utf-7?q?attacker&AEA-[[EXPLOIT_SERVER]_ID]&ACA-?=@ginandjuice.shop
username:timestamp
price
POST /my-account/change-password
=?utf-7?q?&AGEAYgBj-?=foo@ginandjuice.shop
[TEST_USER]:1598530205184
POST /cart/checkout
email
/admin
POST /post/comment
attacker@[[EXPLOIT_SERVER]-ID]
notification
GET /role-selector
DontWannaCry
```

### Bypass Techniques
- 5. Try applying the codes more than once. Notice that if you enter the same code twice in a row, it is rejected because the coupon has already been ap

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

