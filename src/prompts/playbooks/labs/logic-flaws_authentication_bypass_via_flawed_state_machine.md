## Authentication bypass via flawed state machine

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete the usercarlos.

### Solution Steps
1. With Burp running, complete the login process and notice that you need to select your role before you are taken to the home page.
2. Use the content discovery tool to identify the /admin path.
3. Try browsing to /admin directly from the role selection page and observe that this doesn't work.
4. Log out and then go back to the login page. In Burp, turn on proxy intercept then log in.
5. Forward the POST /login request. The next request is GET /role-selector . Drop this request and then browse to the lab's home page. Observe that your role has defaulted to the administrator role and you have access to the admin panel.
6. Delete carlos to solve the lab.

### Key Payloads
- `carlos`
- `wiener:peter`
- `/admin`
- `POST /login`
- `GET /role-selector`
- `administrator`

### Indicators of Success
- Business logic bypassed or manipulated
- Workflow steps skipped or reordered
- Price/quantity manipulation successful
- Negative or extreme values accepted
- State machine or validation violated
---
*Source: PortSwigger Web Security Academy*
