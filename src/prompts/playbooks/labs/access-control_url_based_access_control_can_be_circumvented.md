## URL-based access control can be circumvented

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This website has an unauthenticated admin panel at/admin, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports theX-Original-URLheader.

### Solution Steps
1. Try to load /admin and observe that you get blocked. Notice that the response is very plain, suggesting it may originate from a front-end system.
2. Send the request to Burp Repeater. Change the URL in the request line to / and add the HTTP header X-Original-URL: /invalid . Observe that the application returns a "not found" response. This indicates that the back-end system is processing the URL from the X-Original-URL header.
3. Change the value of the X-Original-URL header to /admin . Observe that you can now access the admin page.
4. To delete carlos , add ?username=carlos to the real query string, and change the X-Original-URL path to /admin/delete .

### Key Payloads
- `/admin`
- `X-Original-URL`
- `carlos`
- `X-Original-URL: /invalid`
- `?username=carlos`
- `/admin/delete`

### Indicators of Success
- Unauthorized resource accessed
- Other user's data visible
- Admin functionality available to regular user
- IDOR allows accessing other records
- Horizontal/vertical privilege escalation
---
*Source: PortSwigger Web Security Academy*
