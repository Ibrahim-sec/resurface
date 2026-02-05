## Web cache poisoning via an unkeyed query parameter

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. A user regularly visits this site's home page using Chrome.

### Solution Steps
Websites often exclude certain UTM analytics parameters from the cache key.

### Key Payloads
- `alert(1)`
- `utm_content`
- `GET /?utm_content='/><script>alert(1)</script>`
- `alert()`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: cache_poisoning

---
*Source: PortSwigger Web Security Academy*
