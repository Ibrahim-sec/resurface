You are a security analyst. Determine if this HTTP response indicates the payload was blocked/filtered.

## Original Payload
```
{payload}
```

## HTTP Response (status {status_code})
```
{response_snippet}
```

## Detection Framework

**Block Detection Signals:**

| Signal | Indicates |
|--------|-----------|
| 403 Forbidden | WAF/ACL block |
| 406 Not Acceptable | Input validation rejection |
| Custom error page with "blocked", "denied", "security" | WAF block page |
| Cloudflare/Akamai/Imperva signatures | CDN WAF triggered |
| Response identical to baseline (no payload reflection) | Payload stripped |
| HTML entities (`&lt;` `&gt;` `&quot;`) in place of `<` `>` `"` | HTML encoding applied |
| Payload partially present | Partial sanitization |
| Connection reset / empty response | Hard block |

**Classification Output:**

- **blocked_waf**: WAF or security middleware intercepted the request
- **blocked_sanitized**: Payload was stripped or encoded (security control worked)
- **blocked_error**: Application error prevented exploitation (not security control)
- **not_blocked**: Payload passed through — check if vulnerability triggered
- **partial_block**: Some payload elements blocked, others passed

**Key Distinction:**
- Security control blocking = the fix is working
- Application error = inconclusive, might still be vulnerable
- Payload passed but no impact = need different payload or approach
