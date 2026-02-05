## DOM XSS in jQuery anchorhrefattribute sink usinglocation.searchsource

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's$selector function to find an anchor element, and changes itshrefattribute using data fromlocation.search.

### Solution Steps
1. On the Submit feedback page, change the query parameter returnPath to / followed by a random alphanumeric string.
2. Right-click and inspect the element, and observe that your random string has been placed inside an a href attribute.
3. Change returnPath to: javascript:alert(document.cookie) Hit enter and click "back".

### Key Payloads
- `href`
- `location.search`
- `document.cookie`
- `returnPath`
- `javascript:alert(document.cookie)`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
