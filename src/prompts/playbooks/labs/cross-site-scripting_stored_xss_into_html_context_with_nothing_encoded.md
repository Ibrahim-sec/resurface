## Stored XSS into HTML context with nothing encoded

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a stored cross-site scripting vulnerability in the comment functionality.

### Solution Steps
1. Enter the following into the comment box: <script>alert(1)</script>
2. Enter a name, email and website.
3. Click "Post comment".
4. Go back to the blog.

### Key Payloads
- `alert`
- `<script>alert(1)</script>`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
