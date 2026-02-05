## Privilege Escalation Playbook

**STRATEGY:** Test if the registration/user API accepts unauthorized role manipulation.

### Steps
1. Use make_request to POST to the registration API with an extra `role:admin` field
2. Use a SIMPLE password you will remember (e.g. 'test123') — you MUST use the EXACT same password to login later
3. Read the API response — if it contains `role":"admin` the vuln is CONFIRMED
4. Login with the EXACT email and password you just registered with
5. Navigate to the admin page to verify access
6. Call report_vulnerability as soon as you have evidence (API accepting role=admin IS enough)

### Indicators of Success
- API response contains elevated role
- Can access admin-only endpoints after registration
- User object shows unexpected permissions

### Common Endpoints to Test
- `/api/Users` (POST with role field)
- `/api/register` 
- `/rest/user/register`
- Profile update endpoints (role modification)
