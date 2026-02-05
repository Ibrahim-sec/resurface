## Broken Access Control Playbook

**STRATEGY:** Test if users can access resources or perform actions beyond their permissions.

### Steps
1. Create two accounts: one regular user, one target (or admin if available)
2. Find resource identifiers: user IDs, document IDs, order numbers
3. As regular user, try accessing other users' resources by changing IDs
4. Try accessing admin functions as regular user
5. If unauthorized access succeeds → CONFIRMED

### Test Scenarios

**Horizontal Privilege Escalation (user → other user):**
- Change `?user_id=123` to `?user_id=124`
- Access `/api/users/124/profile` as user 123
- View/modify another user's orders, documents, settings

**Vertical Privilege Escalation (user → admin):**
- Access `/admin` panel as regular user
- Call admin API endpoints without admin role
- Modify `role` parameter in requests

**IDOR (Insecure Direct Object Reference):**
- Enumerate resource IDs: `/document/1`, `/document/2`
- Predictable IDs: sequential, timestamp-based
- UUID guessing if pattern is known

### Check Points
- Profile/settings pages (other users' data)
- API endpoints with ID parameters
- File download/view functions
- Admin functions and panels
- Report/export features
- Delete/modify operations

### Common Bypasses
- Change HTTP method (GET vs POST)
- Add path traversal: `/user/123/../124/profile`
- Parameter pollution: `?id=123&id=456`
- Case sensitivity: `/Admin` vs `/admin`
- Add trailing characters: `/admin/`, `/admin;`, `/admin.json`
- HTTP header injection: `X-Original-URL: /admin`

### Indicators of Success
- Access to other users' private data
- Admin functions work for regular users
- Resource IDs can be enumerated/predicted
- No server-side authorization checks
