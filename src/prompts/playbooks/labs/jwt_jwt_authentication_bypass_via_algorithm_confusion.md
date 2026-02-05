## JWT authentication bypass via algorithm confusion

**Category:** jwt
**Difficulty:** Expert

### Description
This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

### Solution Steps
1. Login with valid credentials (wiener:peter) and capture your JWT from the session cookie
2. Access /my-account to confirm your current user context
3. Look for exposed public keys - check /.well-known/jwks.json or /jwks.json
4. Extract the RSA public key from the JWKS endpoint
5. Convert the public key to a format suitable for symmetric signing (PEM or base64)
6. The vulnerability: server uses the same verification code for RS256 and HS256
7. Forge a new JWT: change "alg" header from RS256 to HS256
8. Sign the modified token using the RSA public key as the HMAC secret
9. Modify the payload: change "sub" or username claim to "administrator"
10. Send request to /admin with forged token
11. Access admin functionality like /admin/delete?username=carlos
12. The server verifies HS256 signature using public key (which you have), granting admin access

### Key Payloads
- `/admin`
- `carlos`
- `wiener:peter`
- `GET /my-account`
- `administrator`
- `/jwks.json`
- `/.well-known/jwks.json`
- `HS256`
- `RS256`
- `/admin/delete?username=carlos`

### Indicators of Success
- Public key exposed and extractable
- Forged HS256 token accepted by server
- Admin panel accessible with modified token
- User context changes to administrator

---
*Source: PortSwigger Web Security Academy*
