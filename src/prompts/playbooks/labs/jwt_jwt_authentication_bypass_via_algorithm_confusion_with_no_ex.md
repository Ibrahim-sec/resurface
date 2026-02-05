## JWT authentication bypass via algorithm confusion with no exposed key

**Category:** jwt
**Difficulty:** Unknown

### Description
This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

### Solution Steps
You can assume that the server stores its public key as an X.509 PEM file.

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `jwt_forgery.py`
- `GET /my-account`
- `administrator`
- `docker run --rm -it portswigger/sig2n <token1> <token2>`
- `/my-account`
- `/login`
- `HS256`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: jwt

---
*Source: PortSwigger Web Security Academy*
