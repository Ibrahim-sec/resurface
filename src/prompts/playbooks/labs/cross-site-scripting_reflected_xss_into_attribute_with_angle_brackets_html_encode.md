## Reflected XSS into attribute with angle brackets HTML-encoded

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls thealertfunction.

### Solution Steps
Just because you're able to trigger the
alert()
yourself doesn't mean that this will work on the victim. You may need to try injecting your proof-of-concept payload with a variety of different attributes before you find one that successfully executes in the victim's browser.

### Key Payloads
- `alert`
- `alert()`
- `"onmouseover="alert(1)`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
