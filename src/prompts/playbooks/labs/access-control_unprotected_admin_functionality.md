## Unprotected admin functionality

**Category:** broken_access_control
**Difficulty:** Unknown

### Description


### Solution Steps
1. Go to the lab and view robots.txt by appending /robots.txt to the lab URL. Notice that the Disallow line discloses the path to the admin panel.
2. In the URL bar, replace /robots.txt with /administrator-panel to load the admin panel.
3. Delete carlos .

### Key Payloads
- `carlos`
- `robots.txt`
- `/robots.txt`
- `Disallow`
- `/administrator-panel`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: broken_access_control

---
*Source: PortSwigger Web Security Academy*
