## Client-side prototype pollution in third-party libraries

**Category:** prototype_pollution
**Difficulty:** Unknown

### Description
This lab is vulnerable to DOM XSS via client-side prototype pollution. This is due to a gadget in a third-party library, which is easy to miss due to the minified source code. Although it's technically possible to solve this lab manually, we recommend usingDOM Invaderas this will save you a considerable amount of time and effort.

### Solution Steps
1. Load the lab in Burp's built-in browser.
2. Enable DOM Invader and enable the prototype pollution option .
3. Open the browser DevTools panel, go to the DOM Invader tab, then reload the page.
4. Observe that DOM Invader has identified two prototype pollution vectors in the hash property i.e. the URL fragment string.
5. Click Scan for gadgets . A new tab opens in which DOM Invader begins scanning for gadgets using the selected source.
6. When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the DOM Invader tab.
7. Observe that DOM Invader has successfully accessed the setTimeout() sink via the hitCallback gadget.
8. Click Exploit . DOM Invader automatically generates a proof-of-concept exploit and calls alert(1) .
9. Disable DOM Invader.
10. In the browser, go to the lab's exploit server.
11. In the Body section, craft an exploit that will navigate the victim to a malicious URL as follows: <script>
    location="https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>
12. Test the exploit on yourself, making sure that you're navigated to the lab's home page and that the alert(document.cookie) payload is triggered.
13. Go back to the exploit server and deliver the exploit to the victim to solve the lab.

### Key Payloads
- `alert(document.cookie)`
- `hash`
- `setTimeout()`
- `hitCallback`
- `alert(1)`
- `<script>
    location="https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>`

### Indicators of Success
- __proto__ or constructor.prototype modified
- Pollution affects application behavior
- XSS triggered via polluted property
- Server-side pollution causes RCE
- Gadget chain executes
---
*Source: PortSwigger Web Security Academy*
