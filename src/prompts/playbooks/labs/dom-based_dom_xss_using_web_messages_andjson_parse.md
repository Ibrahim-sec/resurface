## DOM XSS using web messages andJSON.parse

**Category:** xss_dom
**Difficulty:** Unknown

### Description
This lab uses web messaging and parses the message as JSON. To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls theprint()function.

### Solution Steps
1. Notice that the home page contains an event listener that listens for a web message. This event listener expects a string that is parsed using JSON.parse() . In the JavaScript, we can see that the event listener expects a type property and that the load-channel case of the switch statement changes the iframe src attribute.
2. Go to the exploit server and add the following iframe to the body, remembering to replace YOUR-LAB-ID with your lab ID: <iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
3. Store the exploit and deliver it to the victim.

### Key Payloads
- `JSON.parse`
- `print()`
- `JSON.parse()`
- `type`
- `load-channel`
- `switch`
- `iframe src`
- `iframe`
- `YOUR-LAB-ID`
- `<iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>`

### Indicators of Success
- DOM sink receives tainted source data
- JavaScript executes via DOM manipulation
- URL fragment or hash value exploited
- postMessage handler vulnerable
- Client-side code processes attacker input
---
*Source: PortSwigger Web Security Academy*
