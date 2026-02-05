## Authentication bypass via information disclosure

**Category:** info_disclosure
**Difficulty:** Unknown

### Description
This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

### Solution Steps
1. In Burp Repeater, browse to GET /admin . The response discloses that the admin panel is only accessible if logged in as an administrator, or if requested from a local IP.
2. Send the request again, but this time use the TRACE method: TRACE /admin
3. Study the response. Notice that the X-Custom-IP-Authorization header, containing your IP address, was automatically appended to your request. This is used to determine whether or not the request came from the localhost IP address.
4. Go to Proxy > Match and replace .
5. Under HTTP match and replace rules , click Add . The Add match/replace rule dialog opens.
6. Leave the Match field empty.
7. Under Type , make sure that Request header is selected.
8. In the Replace field, enter the following: X-Custom-IP-Authorization: 127.0.0.1
9. Click Test .
10. Under Auto-modified request , notice that Burp has added the X-Custom-IP-Authorization header to the modified request.
11. Click OK . Burp Proxy now adds the X-Custom-IP-Authorization header to every request you send.
12. Browse to the home page. Notice that you now have access to the admin panel, where you can delete carlos .

### Key Payloads
- `carlos`
- `wiener:peter`
- `GET /admin`
- `TRACE`
- `TRACE /admin`
- `X-Custom-IP-Authorization`
- `localhost`
- `X-Custom-IP-Authorization: 127.0.0.1`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: info_disclosure

---
*Source: PortSwigger Web Security Academy*
