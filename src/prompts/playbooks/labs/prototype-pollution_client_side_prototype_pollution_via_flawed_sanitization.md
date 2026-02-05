## Client-side prototype pollution via flawed sanitization

**Category:** prototype_pollution
**Difficulty:** Unknown

### Description
This lab is vulnerable to DOM XSS via client-side prototype pollution. Although the developers have implemented measures to prevent prototype pollution, these can be easily bypassed.

### Solution Steps
1. In your browser, try polluting Object.prototype by injecting an arbitrary property via the query string: /?__proto__.foo=bar
2. Open the browser DevTools panel and go to the Console tab.
3. Enter Object.prototype .
4. Study the properties of the returned object and observe that your injected foo property has not been added.
5. Try alternative prototype pollution vectors. For example: /?__proto__[foo]=bar
/?constructor.prototype.foo=bar
6. Observe that in each instance, Object.prototype is not modified.
7. Go to the Sources tab and study the JavaScript files that are loaded by the target site. Notice that deparamSanitized.js uses the sanitizeKey() function defined in searchLoggerFiltered.js to strip potentially dangerous property keys based on a blocklist. However, it does not apply this filter recursively.
8. Back in the URL, try injecting one of the blocked keys in such a way that the dangerous key remains following the sanitization process. For example: /?__pro__proto__to__[foo]=bar
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
9. In the console, enter Object.prototype again. Notice that it now has its own foo property with the value bar . You've successfully found a prototype pollution source and bypassed the website's key sanitization.

### Key Payloads
- `Object.prototype`
- `alert()`
- `/?__proto__.foo=bar`
- `/?__proto__[foo]=bar
/?constructor.prototype.foo=bar`
- `deparamSanitized.js`
- `sanitizeKey()`
- `searchLoggerFiltered.js`
- `/?__pro__proto__to__[foo]=bar
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar`
- `searchLogger.js`
- `config`

### Indicators of Success
- __proto__ or constructor.prototype modified
- Pollution affects application behavior
- XSS triggered via polluted property
- Server-side pollution causes RCE
- Gadget chain executes
---
*Source: PortSwigger Web Security Academy*
