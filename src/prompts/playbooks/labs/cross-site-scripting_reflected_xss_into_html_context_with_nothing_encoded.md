## Reflected XSS into HTML context with nothing encoded

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

### Solution Steps
1. Copy and paste the following into the search box: <script>alert(1)</script>
2. Click "Search".

### Key Payloads
- `alert`
- `<script>alert(1)</script>`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
