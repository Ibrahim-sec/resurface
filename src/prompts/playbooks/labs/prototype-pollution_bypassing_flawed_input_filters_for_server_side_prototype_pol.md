## Bypassing flawed input filters for server-side prototype pollution

**Category:** prototype_pollution
**Difficulty:** Unknown

### Description
This lab is built on Node.js and the Express framework. It is vulnerable to server-side prototype pollution because it unsafely merges user-controllable input into a server-side JavaScript object.

### Solution Steps
1. Log in and visit your account page. Submit the form for updating your billing and delivery address.
2. In Burp, go to the Proxy > HTTP history tab and find the POST /my-account/change-address request.
3. Observe that when you submit the form, the data from the fields is sent to the server as JSON. Notice that the server responds with a JSON object that appears to represent your user. This has been updated to reflect your new address information.
4. Send the request to Burp Repeater.

### Key Payloads
- `Object.prototype`
- `carlos`
- `wiener:peter`
- `POST /my-account/change-address`
- `__proto__`
- `json spaces`
- `"__proto__": {
    "json spaces":10
}`
- `constructor`
- `"constructor": {
    "prototype": {
        "json spaces":10
    }
}`
- `isAdmin`

### Indicators of Success
- __proto__ or constructor.prototype modified
- Pollution affects application behavior
- XSS triggered via polluted property
- Server-side pollution causes RCE
- Gadget chain executes
---
*Source: PortSwigger Web Security Academy*
