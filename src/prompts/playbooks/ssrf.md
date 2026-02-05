## SSRF (Server-Side Request Forgery) Playbook

**STRATEGY:** Find features that fetch external URLs and trick them into accessing internal resources.

### Steps
1. Find URL input fields: image loaders, webhooks, PDF generators, link previews
2. Test with external URL first to confirm fetching works
3. Try internal targets:
   - `http://localhost/admin`
   - `http://127.0.0.1/admin`
   - `http://169.254.169.254/latest/meta-data/` (AWS metadata)
   - `http://[::1]/admin` (IPv6 localhost)
4. If you see internal data or admin panel content → CONFIRMED

### Common Vulnerable Features
- "Fetch URL" / "Import from URL"
- Image/avatar URL fields
- Webhook URLs
- PDF/screenshot generators
- Link preview features
- Stock check APIs (check stockApi parameter)

### Bypass Techniques
- URL encoding: `http://127.0.0.1` → `http://%31%32%37%2e%30%2e%30%2e%31`
- Decimal IP: `http://2130706433` (127.0.0.1 as integer)
- IPv6: `http://[::1]/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/`
- DNS rebinding: Use your own domain that resolves to 127.0.0.1
- Redirect bypass: External URL that 302 redirects to internal
- Protocol smuggling: `file:///etc/passwd`, `gopher://`

### Indicators of Success
- Internal page content returned (admin panels, config files)
- AWS/cloud metadata exposed
- Different response for internal vs blocked URLs
- Error messages revealing internal infrastructure
