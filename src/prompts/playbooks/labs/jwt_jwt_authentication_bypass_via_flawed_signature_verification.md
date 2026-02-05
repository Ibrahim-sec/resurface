## JWT authentication bypass via flawed signature verification

**Category:** jwt
**Difficulty:** Unknown

### Description
This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

### Solution Steps
1. In the lab, log in to your own account.
2. In Burp, go to the Proxy > HTTP history tab and look at the post-login GET /my-account request. Observe that your session cookie is a JWT.
3. Double-click the payload part of the token to view its decoded JSON form in the Inspector panel. Notice that the sub claim contains your username. Send this request to Burp Repeater.
4. In Burp Repeater, change the path to /admin and send the request. Observe that the admin panel is only accessible when logged in as the administrator user.
5. Select the payload of the JWT again. In the Inspector panel, change the value of the sub claim to administrator , then click Apply changes .
6. Select the header of the JWT, then use the Inspector to change the value of the alg parameter to none . Click Apply changes .
7. In the message editor, remove the signature from the JWT, but remember to leave the trailing dot after the payload.
8. Send the request and observe that you have successfully accessed the admin panel.
9. In the response, find the URL for deleting carlos ( /admin/delete?username=carlos ). Send the request to this endpoint to solve the lab.

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `GET /my-account`
- `administrator`
- `none`
- `/admin/delete?username=carlos`

### Indicators of Success
- JWT accepted with modified claims
- Algorithm confusion attack works
- Signature verification bypassed
- User context changed via JWT manipulation
- Admin access achieved with forged token
---
*Source: PortSwigger Web Security Academy*
