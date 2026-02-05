## JWT authentication bypass via kid header path traversal

**Category:** jwt
**Difficulty:** Unknown

### Description
This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses thekidparameter in JWT header to fetch the relevant key from its filesystem.

### Solution Steps
1. In Burp, load the JWT Editor extension from the BApp store.
2. In the lab, log in to your own account and send the post-login GET /my-account request to Burp Repeater.
3. In Burp Repeater, change the path to /admin and send the request. Observe that the admin panel is only accessible when logged in as the administrator user.
4. Go to the JWT Editor Keys tab in Burp's main tab bar.
5. Click New Symmetric Key .
6. In the dialog, click Generate to generate a new key in JWK format. Note that you don't need to select a key size as this will automatically be updated later.
7. Replace the generated value for the k property with a Base64-encoded null byte ( AA== ). Note that this is just a workaround because the JWT Editor extension won't allow you to sign tokens using an empty string.
8. Click OK to save the key.

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `/dev/null`
- `GET /my-account`
- `administrator`
- `AA==`
- `GET /admin`
- `../../../../../../../dev/null`
- `/admin/delete?username=carlos`

### Indicators of Success
- JWT accepted with modified claims
- Algorithm confusion attack works
- Signature verification bypassed
- User context changed via JWT manipulation
- Admin access achieved with forged token
---
*Source: PortSwigger Web Security Academy*
