## Reflected XSS into HTML context with nothing encoded

**Category:** xss_reflected
**Difficulty:** Easy

### Description
This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

### Solution Steps
1. Navigate to the search functionality
2. Enter a test string to see how input is reflected: `test123xss`
3. View page source and confirm the string appears unencoded in HTML
4. No encoding or filtering is applied to the search parameter
5. Inject a basic XSS payload: `<script>alert(1)</script>`
6. Submit the search
7. The script tags are rendered as HTML, executing the JavaScript
8. For exploitation, replace alert with cookie stealing or other payloads

### Key Payloads
- `<script>alert(1)</script>`
- `<script>alert(document.cookie)</script>`
- `<script>alert(document.domain)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`

### Indicators of Success
- Input reflected without HTML encoding
- `<script>` tags rendered as HTML, not text
- alert() popup executes
- View source shows unescaped payload in HTML
- No WAF or filter blocks the payload

---
*Source: PortSwigger Web Security Academy*
