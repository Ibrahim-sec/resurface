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
- Business logic bypassed or manipulated
- Workflow steps skipped or reordered
- Price/quantity manipulation successful
- Negative or extreme values accepted
- State machine or validation violated
---
*Source: PortSwigger Web Security Academy*
