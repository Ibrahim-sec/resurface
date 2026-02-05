## Reflected XSS in a JavaScript URL with some characters blocked

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks.

### Solution Steps
Visit the following URL, replacing
YOUR-LAB-ID
with your lab ID:
https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
The lab will be solved, but the alert will only be called if you click "Back to blog" at the bottom of the page.
The exploit uses exception handling to call the
alert
function with arguments. The
throw
statement is used, separated with a blank comment in order to get round the no spaces restriction. The
alert
function is assigned to the
onerror
exception handler.
As
throw
is a statement, it cannot be used as an expression. Instead, we need to use arrow functions to create a block so that the
throw
statement can be used. We then need to call this function, so we assign it to the
toString
property of
window
and trigger this by forcing a string conversion on
window
.

### Key Payloads
- `alert`
- `1337`
- `YOUR-LAB-ID`
- `https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27`
- `throw`
- `onerror`
- `toString`
- `window`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
