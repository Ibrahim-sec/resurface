## Web cache poisoning via a fat GET request

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is vulnerable to web cache poisoning. It acceptsGETrequests that have a body, but does not include the body in the cache key. A user regularly visits this site's home page using Chrome.

### Solution Steps
1. Observe that every page imports the script /js/geolocate.js , executing the callback function setCountryCookie() . Send the request GET /js/geolocate.js?callback=setCountryCookie to Burp Repeater.
2. Notice that you can control the name of the function that is called in the response by passing in a duplicate callback parameter via the request body. Also notice that the cache key is still derived from the original callback parameter in the request line: GET /js/geolocate.js?callback=setCountryCookie
…
callback=arbitraryFunction

HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
…
arbitraryFunction({"country" : "United Kingdom"})
3. Send the request again, but this time pass in alert(1) as the callback function. Check that you can successfully poison the cache.
4. Remove any cache busters and re-poison the cache. The lab will solve when the victim user visits any page containing this resource import URL.

### Key Payloads
- `alert(1)`
- `/js/geolocate.js`
- `setCountryCookie()`
- `GET /js/geolocate.js?callback=setCountryCookie`
- `callback`
- `GET /js/geolocate.js?callback=setCountryCookie
…
callback=arbitraryFunction

HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
…
arbitraryFunction({"country" : "United Kingdom"})`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: cache_poisoning

---
*Source: PortSwigger Web Security Academy*
