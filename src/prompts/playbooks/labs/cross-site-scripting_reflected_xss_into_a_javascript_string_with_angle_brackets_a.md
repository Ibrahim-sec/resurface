## Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.

### Solution Steps
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript string.
3. Try sending the payload test'payload and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
4. Try sending the payload test\payload and observe that your backslash doesn't get escaped.
5. Replace your input with the following payload to break out of the JavaScript string and inject an alert: \'-alert(1)//
6. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.

### Key Payloads
- `alert`
- `test'payload`
- `test\payload`
- `\'-alert(1)//`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
