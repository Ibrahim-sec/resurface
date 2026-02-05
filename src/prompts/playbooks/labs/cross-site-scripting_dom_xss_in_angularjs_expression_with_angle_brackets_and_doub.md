## DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a DOM-based cross-site scripting vulnerability in a AngularJS expression within the search functionality.

### Solution Steps
1. Enter a random alphanumeric string into the search box.
2. View the page source and observe that your random string is enclosed in an ng-app directive.
3. Enter the following AngularJS expression in the search box: {{$on.constructor('alert(1)')()}}
4. Click search .

### Key Payloads
- `ng-app`
- `alert`
- `{{$on.constructor('alert(1)')()}}`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
