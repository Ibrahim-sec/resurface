## Basic server-side template injection (code context)

**Category:** ssti
**Difficulty:** Unknown

### Description
This lab is vulnerable to server-side template injection due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete themorale.txtfile from Carlos's home directory.

### Solution Steps
Take a closer look at the "preferred name" functionality.

### Key Payloads
- `morale.txt`
- `wiener:peter`
- `POST`
- `blog-post-author-display`
- `user.name`
- `user.first_name`
- `user.nickname`
- `POST /my-account/change-blog-post-author-display`
- `{{someExpression}}`
- `blog-post-author-display=user.name}}{{7*7}}`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: ssti

---
*Source: PortSwigger Web Security Academy*
