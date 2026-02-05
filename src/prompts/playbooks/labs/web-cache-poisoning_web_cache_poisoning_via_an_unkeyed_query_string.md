## Web cache poisoning via an unkeyed query string

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is vulnerable to web cache poisoning because the query string is unkeyed. A user regularly visits this site's home page using Chrome.

### Solution Steps
If you're struggling, you can use the
Pragma: x-get-cache-key
header to display the cache key in the response. This applies to some of the other labs as well.
Although you can't use a query parameter as a cache buster, there is a common request header that will be keyed if present. You can use the
Param Miner
extension to automatically add a cache buster header to your requests.

### Key Payloads
- `alert(1)`
- `Pragma: x-get-cache-key`
- `Origin`
- `GET /?evil='/><script>alert(1)</script>`
- `X-Cache: hit`

### Indicators of Success
- Unkeyed input reflected in cached response
- X-Cache: hit with poisoned content
- Victim receives attacker-controlled response
- XSS executes via cached response
- Cache key manipulation successful
---
*Source: PortSwigger Web Security Academy*
