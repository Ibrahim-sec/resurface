## User ID controlled by request parameter

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab has a horizontal privilege escalation vulnerability on the user account page.

### Solution Steps
1. Log in using the supplied credentials and go to your account page.
2. Note that the URL contains your username in the "id" parameter.
3. Send the request to Burp Repeater.
4. Change the "id" parameter to carlos .
5. Retrieve and submit the API key for carlos .

### Key Payloads
- `carlos`
- `wiener:peter`

### Indicators of Success
- Unauthorized resource accessed
- Other user's data visible
- Admin functionality available to regular user
- IDOR allows accessing other records
- Horizontal/vertical privilege escalation
---
*Source: PortSwigger Web Security Academy*
