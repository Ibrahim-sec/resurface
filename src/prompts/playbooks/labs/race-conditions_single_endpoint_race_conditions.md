## Single-endpoint race conditions

**Category:** race_condition
**Difficulty:** Unknown

### Description
This lab's email change feature contains a race condition that enables you to associate an arbitrary email address with your account.

### Solution Steps
1. Log in and attempt to change your email to anything@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net . Observe that a confirmation email is sent to your intended new address, and you're prompted to click a link containing a unique token to confirm the change.
2. Complete the process and confirm that your email address has been updated on your account page.
3. Try submitting two different @exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net email addresses in succession, then go to the email client.
4. Notice that if you try to use the first confirmation link you received, this is no longer valid. From this, you can infer that the website only stores one pending email address at a time. As submitting a new email address edits this entry in the database rather than appending to it, there is potential for a collision.

### Key Payloads
- `carlos@ginandjuice.shop`
- `carlos`
- `wiener:peter`
- `@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net`
- `anything@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net`
- `POST /my-account/change-email`
- `test1@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net, test2@..., test3@...`
- `email`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: race_condition

---
*Source: PortSwigger Web Security Academy*
