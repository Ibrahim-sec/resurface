## Weak isolation on dual-use endpoint

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab makes a flawed assumption about the user's privilege level based on their input. As a result, you can exploit the logic of its account management features to gain access to arbitrary users' accounts. To solve the lab, access theadministratoraccount and delete the usercarlos.

### Solution Steps
1. With Burp running, log in and access your account page.
2. Change your password.
3. Study the POST /my-account/change-password request in Burp Repeater.
4. Notice that if you remove the current-password parameter entirely, you are able to successfully change your password without providing your current one.
5. Observe that the user whose password is changed is determined by the username parameter. Set username=administrator and send the request again.
6. Log out and notice that you can now successfully log in as the administrator using the password you just set.
7. Go to the admin panel and delete carlos to solve the lab.

### Key Payloads
- `administrator`
- `carlos`
- `wiener:peter`
- `POST /my-account/change-password`
- `current-password`
- `username`
- `username=administrator`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: logic_flaw

---
*Source: PortSwigger Web Security Academy*
