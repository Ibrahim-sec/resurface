## Inconsistent handling of exceptional input

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab doesn't adequately validate user input. You can exploit a logic flaw in its account registration process to gain access to administrative functionality. To solve the lab, access the admin panel and delete the usercarlos.

### Solution Steps
You can use the link in the lab banner to access an email client connected to your own private mail server. The client will display all messages sent to
@YOUR-EMAIL-ID.web-security-academy.net
and any arbitrary subdomains. Your unique email ID is displayed in the email client.

### Key Payloads
- `carlos`
- `@YOUR-EMAIL-ID.web-security-academy.net`
- `/admin`
- `DontWannaCry`
- `very-long-string@YOUR-EMAIL-ID.web-security-academy.net`
- `very-long-string`
- `dontwannacry.com`
- `very-long-string@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net`
- `@dontwannacry.com`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: logic_flaw

---
*Source: PortSwigger Web Security Academy*
