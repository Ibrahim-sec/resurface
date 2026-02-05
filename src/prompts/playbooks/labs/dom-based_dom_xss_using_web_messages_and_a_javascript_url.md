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
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_dom

---
*Source: PortSwigger Web Security Academy*
