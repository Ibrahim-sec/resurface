## Web cache poisoning with an unkeyed cookie

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executesalert(1)in the visitor's browser.

### Solution Steps
1. With Burp running, load the website's home page.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Notice that the first response you received sets the cookie fehost=prod-cache-01 .
3. Reload the home page and observe that the value from the fehost cookie is reflected inside a double-quoted JavaScript object in the response.
4. Send this request to Burp Repeater and add a cache-buster query parameter.
5. Change the value of the cookie to an arbitrary string and resend the request. Confirm that this string is reflected in the response.
6. Place a suitable XSS payload in the fehost cookie, for example: fehost=someString"-alert(1)-"someString
7. Replay the request until you see the payload in the response and X-Cache: hit in the headers.
8. Load the URL in the browser and confirm the alert() fires.
9. Go back Burp Repeater, remove the cache buster, and replay the request to keep the cache poisoned until the victim visits the site and the lab is solved.

### Key Payloads
- `alert(1)`
- `fehost=prod-cache-01`
- `fehost`
- `fehost=someString"-alert(1)-"someString`
- `X-Cache: hit`
- `alert()`

### Indicators of Success
- Unkeyed input reflected in cached response
- X-Cache: hit with poisoned content
- Victim receives attacker-controlled response
- XSS executes via cached response
- Cache key manipulation successful
---
*Source: PortSwigger Web Security Academy*
