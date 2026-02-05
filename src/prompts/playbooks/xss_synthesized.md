## XSS Playbook
*Synthesized from 30 PortSwigger labs*

### Overview
This playbook covers 30 known attack techniques for xss.

### Attack Techniques

**Bypass Techniques:**
- Reflected XSS protected by CSP, with CSP bypass
- Exploiting XSS to bypass CSRF defenses

**DOM-based:**
- DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
- DOM XSS indocument.writesink using sourcelocation.search
- DOM XSS indocument.writesink using sourcelocation.searchinside a select element
- Reflected DOM XSS
- Stored DOM XSS
- DOM XSS ininnerHTMLsink using sourcelocation.search
- DOM XSS in jQuery anchorhrefattribute sink usinglocation.searchsource
- DOM XSS in jQuery selector sink using a hashchange event

**General:**
- Exploiting cross-site scripting to capture passwords
- Exploiting cross-site scripting to steal cookies

**Reflected:**
- Reflected XSS protected by very strict CSP, with dangling markup attack
- Reflected XSS with AngularJS sandbox escape and CSP
- Reflected XSS with AngularJS sandbox escape without strings
- Reflected XSS into attribute with angle brackets HTML-encoded
- Reflected XSS in canonical link tag
- Reflected XSS with event handlers andhrefattributes blocked
- Reflected XSS into HTML context with all tags blocked except custom ones
- Reflected XSS into HTML context with most tags and attributes blocked

**Stored/Persistent:**
- Stored XSS into anchorhrefattribute with double quotes HTML-encoded
- Stored XSS intoonclickevent with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
- Stored XSS into HTML context with nothing encoded

### Key Payloads
```
hacker@evil-user.net
form-action
unsafe-inline
charAt
storeId
CTRL+ALT+X
onresize
ALT+SHIFT+X
<iframe src="https://[LAB_ID].[TARGET]/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
email
report-uri
$eval
script-src-elem
https://[LAB_ID].[TARGET]/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
toString()
<img src onerror=alert(1)>
<a href="">Click me</a>
<title>
searchResults.js
"XSS"
```

### Bypass Techniques
- function to encode angle brackets. However, when the first argument is a string, the function only replaces the first occurrence. We exploit this vuln

### Indicators of Success
- Unexpected data in response
- Error messages revealing internal info
- Behavior change confirming injection
- Out-of-band callback received
- Access to unauthorized resources

### Testing Methodology
1. **Identify injection points** — forms, parameters, headers, cookies
2. **Test basic payloads** — start simple, escalate complexity
3. **Observe responses** — errors, timing, content changes
4. **Try bypasses** — encoding, alternative syntax, filter evasion
5. **Confirm impact** — data extraction, privilege escalation, RCE

