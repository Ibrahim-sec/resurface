## Stored DOM XSS

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab demonstrates a stored DOM vulnerability in the blog comment functionality. To solve this lab, exploit this vulnerability to call thealert()function.

### Solution Steps
Post a comment containing the following vector:
<><img src=1 onerror=alert(1)>
In an attempt to prevent XSS, the website uses the JavaScript
replace()
function to encode angle brackets. However, when the first argument is a string, the function only replaces the first occurrence. We exploit this vulnerability by simply including an extra set of angle brackets at the beginning of the comment. These angle brackets will be encoded, but any subsequent angle brackets will be unaffected, enabling us to effectively bypass the filter and inject HTML.

### Key Payloads
- `alert()`
- `<><img src=1 onerror=alert(1)>`
- `replace()`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
