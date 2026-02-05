## IDOR (Insecure Direct Object Reference) Playbook

**STRATEGY:** Access resources belonging to other users by manipulating IDs.

### Steps
1. Use make_request to try sequential IDs: GET /api/Users/1, /api/Users/2, etc.
2. Try accessing other users' data: /api/Baskets/1, /api/Baskets/2
3. If you can see data that doesn't belong to you → CONFIRMED
4. Compare responses between your own ID and other IDs

### Indicators of Success
- Can read other users' data by changing ID
- Can modify other users' resources
- No authorization check on resource access

### Common Patterns
- Sequential numeric IDs: `/api/users/1`, `/api/users/2`
- UUIDs (try known UUIDs from other responses)
- Encoded IDs (base64, etc.)
- File paths: `/files/user1/doc.pdf`
