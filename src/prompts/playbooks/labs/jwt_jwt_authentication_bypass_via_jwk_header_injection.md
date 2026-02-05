## JWT authentication bypass via jwk header injection

**Category:** jwt
**Difficulty:** Unknown

### Description
This lab uses a JWT-based mechanism for handling sessions. The server supports thejwkparameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

### Solution Steps
1. In Burp, load the JWT Editor extension from the BApp store.
2. In the lab, log in to your own account and send the post-login GET /my-account request to Burp Repeater.
3. In Burp Repeater, change the path to /admin and send the request. Observe that the admin panel is only accessible when logged in as the administrator user.
4. Go to the JWT Editor Keys tab in Burp's main tab bar.
5. Click New RSA Key .
6. In the dialog, click Generate to automatically generate a new key pair, then click OK to save the key. Note that you don't need to select a key size as this will automatically be updated later.
7. Go back to the GET /admin request in Burp Repeater and switch to the extension-generated JSON Web Token tab.
8. In the payload, change the value of the sub claim to administrator .
9. At the bottom of the JSON Web Token tab, click Attack , then select Embedded JWK . When prompted, select your newly generated RSA key and click OK .
10. In the header of the JWT, observe that a jwk parameter has been added containing your public key.
11. Send the request. Observe that you have successfully accessed the admin panel.
12. In the response, find the URL for deleting carlos ( /admin/delete?username=carlos ). Send the request to this endpoint to solve the lab.

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `GET /my-account`
- `administrator`
- `GET /admin`
- `JSON Web Token`
- `/admin/delete?username=carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: jwt

---
*Source: PortSwigger Web Security Academy*
