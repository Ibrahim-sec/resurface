## Reflected XSS with some SVG markup allowed

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab has a simple reflected XSS vulnerability. The site is blocking common tags but misses some SVG tags and events.

### Solution Steps
1. Inject a standard XSS payload, such as: <img src=1 onerror=alert(1)>
2. Observe that this payload gets blocked. In the next few steps, we'll use Burp Intruder to test which tags and attributes are being blocked.
3. Open Burp's browser and use the search function in the lab. Send the resulting request to Burp Intruder.
4. In the request template, replace the value of the search term with: <>
5. Place the cursor between the angle brackets and click Add § to create a payload position. The value of the search term should now be: <§§>
6. Visit the XSS cheat sheet and click Copy tags to clipboard .
7. In Burp Intruder, in the Payloads side panel, click Paste to paste the list of tags into the payloads list. Click Start attack .
8. When the attack is finished, review the results. Observe that all payloads caused a 400 response, except for the ones using the <svg> , <animatetransform> , <title> , and <image> tags, which received a 200 response.
9. Go back to the Intruder tab and replace your search term with: <svg><animatetransform%20=1>
10. Place the cursor before the = character and click Add § to create a payload position. The value of the search term should now be: <svg><animatetransform%20§§=1>
11. Visit the XSS cheat sheet and click Copy events to clipboard .
12. In Burp Intruder, in the Payloads side panel, click Clear to remove the previous payloads. Then click Paste to paste the list of attributes into the payloads list. Click Start attack .
13. When the attack is finished, review the results. Note that all payloads caused a 400 response, except for the onbegin payload, which caused a 200 response. Visit the following URL in the browser to confirm that the alert() function is called and the lab is solved: https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E

### Key Payloads
- `alert()`
- `<img src=1 onerror=alert(1)>`
- `<§§>`
- `<svg>`
- `<animatetransform>`
- `<title>`
- `<image>`
- `<svg><animatetransform%20=1>`
- `<svg><animatetransform%20§§=1>`
- `onbegin`

### Indicators of Success
- Payload reflected in response without encoding
- `<script>` tags rendered as HTML elements
- JavaScript alert/print executes in browser
- DOM shows injected elements
- No WAF block or sanitization
---
*Source: PortSwigger Web Security Academy*
