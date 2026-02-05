## CLICKJACKING Playbook
*Synthesized from 5 PortSwigger labs*

### Overview
This playbook covers 5 known attack techniques for clickjacking.

### Attack Techniques

**DOM-based:**
- Exploiting clickjacking vulnerability to trigger DOM-based XSS

**General:**
- Basic clickjacking with CSRF token protection
- Clickjacking with a frame buster script
- Multistep clickjacking
- Clickjacking with form input data prefilled from a URL parameter

### Key Payloads
```
$opacity
$width_value
$top_value
$side_value
$height_value
print()
$top_value2
[TEST_USER]:[TEST_PASS]
$side_value2
secondClick
$side_value1
firstClick
sandbox="allow-forms"
[LAB_ID]
left
$top_value1
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

