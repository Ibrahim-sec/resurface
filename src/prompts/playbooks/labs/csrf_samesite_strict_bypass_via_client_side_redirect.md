## SameSite Strict bypass via client-side redirect

**Category:** csrf
**Difficulty:** Unknown

### Description
This lab's change email function is vulnerable to CSRF. To solve the lab, perform a CSRF attack that changes the victim's email address. You should use the provided exploit server to host your attack.

### Solution Steps
You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

### Key Payloads
- `wiener:peter`
- `POST /my-account/change-email`
- `POST /login`
- `SameSite=Strict`
- `/post/comment/confirmation?postId=x`
- `/resources/js/commentConfirmationRedirect.js`
- `postId`
- `GET /post/comment/confirmation?postId=x`
- `/post/comment/confirmation?postId=foo`
- `/post/foo`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: csrf

---
*Source: PortSwigger Web Security Academy*
