## Parameter cloaking

**Category:** cache_poisoning
**Difficulty:** Expert

### Description
This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. There is also inconsistent parameter parsing between the cache and the back-end. A user regularly visits this site's home page using Chrome.

### Solution Steps
1. Explore the application and identify cacheable resources
2. Find a JavaScript file loaded by the homepage: /js/geolocate.js
3. Notice it accepts a callback parameter: /js/geolocate.js?callback=setCountryCookie
4. The utm_content parameter is excluded from the cache key (analytics tracking)
5. Discover parameter parsing inconsistency between cache and backend
6. The cache parses utm_content=foo;callback=evil as one parameter
7. The backend parses the semicolon as a delimiter, seeing two parameters
8. Craft payload with parameter cloaking:
9. `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)`
10. Cache sees: callback=setCountryCookie, utm_content=foo;callback=alert(1)
11. Backend sees: callback=setCountryCookie, utm_content=foo, callback=alert(1)
12. Backend uses last callback value: alert(1)
13. Cache stores response under key without utm_content
14. Victim requests /js/geolocate.js?callback=setCountryCookie and gets poisoned response
15. alert(1) executes in victim's browser

### Key Payloads
- `alert(1)`
- `utm_content`
- `/js/geolocate.js`
- `setCountryCookie`
- `callback`
- `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)`
- `;` (semicolon delimiter)

### Indicators of Success
- utm_content excluded from X-Cache-Key
- Semicolon parsed differently by cache vs backend
- Response contains alert(1) as callback function
- Cached response served to victims
- XSS executes on victim visit

---
*Source: PortSwigger Web Security Academy*
