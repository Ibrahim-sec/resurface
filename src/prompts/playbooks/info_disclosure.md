## Information Disclosure Playbook

**STRATEGY:** Find endpoints that expose sensitive data.

### Steps
1. Use make_request to probe common sensitive endpoints:
   - GET /api/Users
   - GET /rest/admin
   - GET /api/SecurityQuestions
2. Check for exposed data in page source or API responses
3. If you find emails, passwords, tokens, or internal config → CONFIRMED

### Indicators of Success
- API returns list of users with sensitive fields
- Internal configuration exposed
- Debug information in responses
- Stack traces with code paths

### Common Endpoints to Check
- `/api/users`, `/api/Users`
- `/admin`, `/rest/admin`
- `/debug`, `/trace`
- `/.env`, `/config.json`
- `/api/swagger`, `/api/docs`
