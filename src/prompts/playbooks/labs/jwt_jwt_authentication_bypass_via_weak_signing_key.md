## JWT authentication bypass via weak signing key

**Category:** jwt
**Difficulty:** Unknown

### Description
This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using awordlist of common secrets.

### Solution Steps
1. In Burp, load the JWT Editor extension from the BApp store.
2. In the lab, log in to your own account and send the post-login GET /my-account request to Burp Repeater.
3. In Burp Repeater, change the path to /admin and send the request. Observe that the admin panel is only accessible when logged in as the administrator user.
4. Copy the JWT and brute-force the secret. You can do this using hashcat as follows: hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list If you're using hashcat, this outputs the JWT, followed by the secret. If everything worked correctly, this should reveal that the weak secret is secret1 .

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `GET /my-account`
- `administrator`
- `hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list`
- `secret1`
- `--show`
- `GET /admin`
- `Sign`

### Indicators of Success
- JWT accepted with modified claims
- Algorithm confusion attack works
- Signature verification bypassed
- User context changed via JWT manipulation
- Admin access achieved with forged token
---
*Source: PortSwigger Web Security Academy*
