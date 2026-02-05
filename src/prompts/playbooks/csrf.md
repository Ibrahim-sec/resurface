## CSRF (Cross-Site Request Forgery) Playbook

**STRATEGY:** Check if sensitive actions can be performed without CSRF tokens or proper validation.

### Steps
1. Find state-changing actions: password change, email update, account settings
2. Intercept the request and note if there's a CSRF token
3. Test without the token or with an invalid token
4. If action succeeds without valid CSRF token → CONFIRMED
5. Check SameSite cookie attribute and Referer validation

### Key Checks
- Does the form have a CSRF token field?
- Does removing the token cause the request to fail?
- Does an invalid/random token get rejected?
- Can you change Content-Type to bypass protection?
- Is Referer header validated?

### Bypass Techniques
- Remove CSRF token entirely
- Use empty token value
- Reuse old/expired token
- Change request method (POST → GET)
- Change Content-Type: `text/plain` or `application/x-www-form-urlencoded`
- Remove Referer header
- Subdomain Referer bypass

### Test Actions
- Change email/password
- Transfer money/points
- Change account settings
- Add/remove users
- Admin functions

### Indicators of Success
- Sensitive action completes without CSRF token
- Action works from different origin
- Token not tied to user session
