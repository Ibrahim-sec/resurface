## File path traversal, validation of file extension with null byte bypass

**Category:** path_traversal
**Difficulty:** Unknown

### Description
This lab contains a path traversal vulnerability in the display of product images.

### Solution Steps
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the filename parameter, giving it the value: ../../../etc/passwd%00.png
3. Observe that the response contains the contents of the /etc/passwd file.

### Key Payloads
- `/etc/passwd`
- `filename`
- `../../../etc/passwd%00.png`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: path_traversal

---
*Source: PortSwigger Web Security Academy*
