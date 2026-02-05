## DOM-based open redirection

**Category:** xss_dom
**Difficulty:** Unknown

### Description
This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.

### Solution Steps
The blog post page contains the following link, which returns to the home page of the blog:
<a href='#' onclick='returnURL' = /url=https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
The
url
parameter contains an open redirection vulnerability that allows you to change where the "Back to Blog" link takes the user. To solve the lab, construct and visit the following URL, remembering to change the URL to contain your lab ID and your exploit server ID:
https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/

### Key Payloads
- `<a href='#' onclick='returnURL' = /url=https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>`
- `https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/`

### Indicators of Success
- DOM sink receives tainted source data
- JavaScript executes via DOM manipulation
- URL fragment or hash value exploited
- postMessage handler vulnerable
- Client-side code processes attacker input
---
*Source: PortSwigger Web Security Academy*
