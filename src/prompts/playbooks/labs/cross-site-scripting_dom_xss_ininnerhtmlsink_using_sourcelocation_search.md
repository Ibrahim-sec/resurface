## DOM XSS ininnerHTMLsink using sourcelocation.search

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses aninnerHTMLassignment, which changes the HTML contents of adivelement, using data fromlocation.search.

### Solution Steps
1. Enter the following into the into the search box: <img src=1 onerror=alert(1)>
2. Click "Search".

### Key Payloads
- `innerHTML`
- `location.search`
- `alert`
- `<img src=1 onerror=alert(1)>`
- `onerror`
- `alert()`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
