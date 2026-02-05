## JWT authentication bypass via algorithm confusion with no exposed key

**Category:** jwt
**Difficulty:** Expert

### Description
This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

### Solution Steps
1. Login with valid credentials (wiener:peter) to get your first JWT
2. Logout and login again to get a second JWT signed by the same key
3. No public key is exposed, so you must derive it from the signed tokens
4. Use the sig2n tool to derive the public key: `docker run --rm -it portswigger/sig2n <token1> <token2>`
5. The tool performs a mathematical attack using two tokens signed by the same RSA key
6. It outputs potential public keys in various formats (X.509 PEM, PKCS1)
7. For each candidate key, attempt the algorithm confusion attack
8. Change the JWT header "alg" from RS256 to HS256
9. Modify payload to set username/sub to "administrator"
10. Sign with the derived public key as HMAC secret
11. Test the forged token against /my-account until one works
12. Use the working forged admin token to access /admin and delete carlos

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `docker run --rm -it portswigger/sig2n <token1> <token2>`
- `jwt_forgery.py`
- `GET /my-account`
- `administrator`
- `/login`
- `HS256`
- `RS256`

### Indicators of Success
- Two valid JWTs obtained from same server
- sig2n tool derives candidate public keys
- Forged HS256 token accepted by server
- Admin access achieved with modified claims

---
*Source: PortSwigger Web Security Academy*
