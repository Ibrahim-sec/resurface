## Client-side prototype pollution via browser APIs

**Category:** prototype_pollution
**Difficulty:** Unknown

### Description
This lab is vulnerable to DOM XSS via client-side prototype pollution. The website's developers have noticed a potential gadget and attempted to patch it. However, you can bypass the measures they've taken.

### Solution Steps
1. In your browser, try polluting Object.prototype by injecting an arbitrary property via the query string: /?__proto__[foo]=bar
2. Open the browser DevTools panel and go to the Console tab.
3. Enter Object.prototype .
4. Study the properties of the returned object and observe that your injected foo property has been added. You've successfully found a prototype pollution source.

### Key Payloads
- `Object.prototype`
- `alert()`
- `/?__proto__[foo]=bar`
- `searchLoggerConfigurable.js`
- `config`
- `transport_url`
- `Object.defineProperty()`
- `value`
- `/?__proto__[value]=foo`
- `<script>`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: prototype_pollution

---
*Source: PortSwigger Web Security Academy*
