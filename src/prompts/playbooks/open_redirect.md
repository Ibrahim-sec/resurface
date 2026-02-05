## Open Redirect Playbook

**STRATEGY:** Find redirect parameters and trick them into sending users to malicious sites.

### Steps
1. Look for redirect/return URL parameters: `?redirect=`, `?url=`, `?next=`, `?return=`
2. Find login/logout flows that redirect after action
3. Test with external URL: `?redirect=https://evil.com`
4. If browser redirects to external domain → CONFIRMED
5. Check for path-based redirects: `/redirect?url=/dashboard` → try `//evil.com`

### Common Parameters
- `redirect`, `redirect_uri`, `redirect_url`
- `return`, `returnUrl`, `return_to`
- `next`, `nextUrl`, `continue`
- `url`, `uri`, `path`, `goto`
- `dest`, `destination`, `target`
- `rurl`, `redir`, `out`

### Bypass Techniques
- Protocol-relative: `//evil.com`
- Backslash: `\/\/evil.com` or `/\evil.com`
- URL encoding: `%2f%2fevil.com`
- @ symbol: `https://legit.com@evil.com`
- Null byte: `https://legit.com%00.evil.com`
- Parameter pollution: `?redirect=legit.com&redirect=evil.com`
- Path bypass: `/redirect/https://evil.com`

### Indicators of Success
- Browser URL changes to attacker-controlled domain
- No warning or interstitial before redirect
- Works with any external domain
