## XSS Reflected Playbook

**STRATEGY:** Find input fields that reflect user input in the page.

### Steps
1. Find search bars, URL parameters, or form fields
2. Type the XSS payload: `<iframe src="javascript:alert('xss')">`
3. Press Enter to submit
4. If a JavaScript dialog/alert appears → CONFIRMED, report immediately
5. If you see your payload rendered as HTML in the page → CONFIRMED
6. If the payload is escaped/filtered, try: `<img src=x onerror=alert(1)>`

### Indicators of Success
- JavaScript alert/confirm/prompt dialog appears
- Payload appears unescaped in page source
- `<script>` tags execute

### Common Bypass Techniques
- URL encoding: `%3Cscript%3E`
- Case variation: `<ScRiPt>`
- Alternative tags: `<svg onload=alert(1)>`
- Event handlers: `<img src=x onerror=alert(1)>`
