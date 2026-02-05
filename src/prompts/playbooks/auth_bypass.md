## Authentication Bypass Playbook

**STRATEGY:** Find ways to access protected resources without proper authentication.

### Steps
1. Try accessing admin/protected URLs directly without logging in
2. Test SQL injection in login: `' OR 1=1--`
3. Check for default credentials: admin/admin, admin/password
4. Test JWT/session manipulation
5. If you gain access without valid credentials → CONFIRMED

### Common Techniques

**Direct Access:**
- Navigate to `/admin`, `/dashboard`, `/api/users` without auth
- Force browse to protected resources
- Check if authentication is client-side only

**SQL Injection Auth Bypass:**
- Username: `admin'--`
- Username: `' OR 1=1--`
- Password: `' OR '1'='1`
- Bypass login entirely via SQLi

**Default/Weak Credentials:**
- admin/admin, admin/password, admin/123456
- root/root, root/toor
- test/test, guest/guest
- Application-specific defaults

**Session/Token Manipulation:**
- Change `isAdmin=false` to `isAdmin=true` in cookies
- Modify JWT payload (if weak secret)
- Reuse another user's session token
- Session fixation attacks

**Parameter Manipulation:**
- Add `?admin=true` or `&role=admin`
- Modify hidden form fields
- Change user ID in requests

### Indicators of Success
- Access to admin panel without login
- Login succeeds with SQLi payload
- Session token grants unauthorized access
- Protected API endpoints respond with data
