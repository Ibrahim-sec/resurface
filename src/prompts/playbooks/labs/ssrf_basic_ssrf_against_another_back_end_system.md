## Basic SSRF against another back-end system

**Category:** ssrf
**Difficulty:** Unknown

### Description
This lab has a stock check feature which fetches data from an internal system.

### Solution Steps
1. Visit a product, click Check stock , intercept the request in Burp Suite, and send it to Burp Intruder.
2. Change the stockApi parameter to http://192.168.0.1:8080/admin then highlight the final octet of the IP address (the number 1 ) and click Add § .
3. In the Payloads side panel, change the payload type to Numbers , and enter 1, 255, and 1 in the From and To and Step boxes respectively.
4. Click Start attack .
5. Click on the Status column to sort it by status code ascending. You should see a single entry with a status of 200 , showing an admin interface.
6. Click on this request, send it to Burp Repeater, and change the path in the stockApi to: /admin/delete?username=carlos

### Key Payloads
- `192.168.0.X`
- `8080`
- `carlos`
- `stockApi`
- `http://192.168.0.1:8080/admin`
- `/admin/delete?username=carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: ssrf

---
*Source: PortSwigger Web Security Academy*
