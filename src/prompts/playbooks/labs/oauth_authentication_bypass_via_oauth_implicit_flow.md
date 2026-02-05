## Authentication bypass via OAuth implicit flow

**Category:** oauth
**Difficulty:** Unknown

### Description
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

### Solution Steps
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that make up the OAuth flow. This starts from the authorization request GET /auth?client_id=[...] .
3. Notice that the client application (the blog website) receives some basic information about the user from the OAuth service. It then logs the user in by sending a POST request containing this information to its own /authenticate endpoint, along with the access token.
4. Send the POST /authenticate request to Burp Repeater. In Repeater, change the email address to carlos@carlos-montoya.net and send the request. Observe that you do not encounter an error.
5. Right-click on the POST request and select "Request in browser" > "In original session". Copy this URL and visit it in the browser. You are logged in as Carlos and the lab is solved.

### Key Payloads
- `carlos@carlos-montoya.net`
- `wiener:peter`
- `GET /auth?client_id=[...]`
- `POST`
- `/authenticate`
- `POST /authenticate`

### Indicators of Success
- OAuth token stolen via redirect manipulation
- Account linked to attacker's OAuth
- Authorization code intercepted
- Token leakage via referrer
- CSRF in OAuth flow exploited
---
*Source: PortSwigger Web Security Academy*
