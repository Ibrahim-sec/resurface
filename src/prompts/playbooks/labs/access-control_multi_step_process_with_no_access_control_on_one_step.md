## Multi-step process with no access control on one step

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentialsadministrator:admin.

### Solution Steps
1. Log in using the admin credentials.
2. Browse to the admin panel, promote carlos , and send the confirmation HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Copy the non-admin user's session cookie into the existing Repeater request, change the username to yours, and replay it.

### Key Payloads
- `administrator:admin`
- `wiener:peter`
- `carlos`

### Indicators of Success
- Unauthorized resource accessed
- Other user's data visible
- Admin functionality available to regular user
- IDOR allows accessing other records
- Horizontal/vertical privilege escalation
---
*Source: PortSwigger Web Security Academy*
