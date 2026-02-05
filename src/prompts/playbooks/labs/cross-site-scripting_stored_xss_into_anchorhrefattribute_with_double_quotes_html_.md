## Stored XSS into anchorhrefattribute with double quotes HTML-encoded

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls thealertfunction when the comment author name is clicked.

### Solution Steps
1. Post a comment with a random alphanumeric string in the "Website" input, then use Burp Suite to intercept the request and send it to Burp Repeater.
2. Make a second request in the browser to view the post and use Burp Suite to intercept the request and send it to Burp Repeater.
3. Observe that the random string in the second Repeater tab has been reflected inside an anchor href attribute.
4. Repeat the process again but this time replace your input with the following payload to inject a JavaScript URL that calls alert: javascript:alert(1)
5. Verify the technique worked by right-clicking, selecting "Copy URL", and pasting the URL in the browser. Clicking the name above your comment should trigger an alert.

### Key Payloads
- `href`
- `alert`
- `javascript:alert(1)`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
