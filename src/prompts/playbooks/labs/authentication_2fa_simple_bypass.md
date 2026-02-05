## 2FA simple bypass

**Category:** auth_bypass
**Difficulty:** Unknown

### Description
This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

### Solution Steps
1. Log in to your own account. Your 2FA verification code will be sent to you by email. Click the Email client button to access your emails.
2. Go to your account page and make a note of the URL.
3. Log out of your account.
4. Log in using the victim's credentials.
5. When prompted for the verification code, manually change the URL to navigate to /my-account . The lab is solved when the page loads.

### Key Payloads
- `wiener:peter`
- `carlos:montoya`
- `/my-account`

### Indicators of Success
- Access granted without valid credentials
- Session token accepted for different user
- Admin panel accessible
- Authentication step skipped
- User context changed to target account
---
*Source: PortSwigger Web Security Academy*
