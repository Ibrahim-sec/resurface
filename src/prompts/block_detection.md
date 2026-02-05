You are a security analyst. Determine if this HTTP response indicates the payload was blocked/filtered.

## Original Payload
```
{payload}
```

## HTTP Response (status {status_code})
```
{response_snippet}
```

Analyze whether the response indicates:
- The payload was blocked by a WAF
- The payload was stripped/sanitized
- The payload was HTML-escaped
- An error page was returned
- The payload went through unchanged
