## DOM XSS indocument.writesink using sourcelocation.search

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScriptdocument.writefunction, which writes data out to the page. Thedocument.writefunction is called with data fromlocation.search, which you can control using the website URL.

### Solution Steps
1. Enter a random alphanumeric string into the search box.
2. Right-click and inspect the element, and observe that your random string has been placed inside an img src attribute.
3. Break out of the img attribute by searching for: "><svg onload=alert(1)>

### Key Payloads
- `document.write`
- `location.search`
- `alert`
- `img src`
- `"><svg onload=alert(1)>`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
