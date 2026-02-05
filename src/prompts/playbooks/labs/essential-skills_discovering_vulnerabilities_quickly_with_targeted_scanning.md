## Discovering vulnerabilities quickly with targeted scanning

**Category:** essential-skills
**Difficulty:** Easy

### Description
This lab contains a vulnerability that enables you to read arbitrary files from the server. To solve the lab, retrieve the contents of /etc/passwd within 10 minutes.

### Solution Steps
1. Start by mapping the application - identify all endpoints and parameters
2. Look for file-related functionality: image loading, file downloads, includes
3. Use automated scanning (Burp Scanner or similar) with active scan on promising endpoints
4. Focus on parameters that might reference files: path, file, document, page, include
5. Common vulnerability classes for file reading: Path Traversal, LFI, XXE
6. Test path traversal patterns: `../../../etc/passwd`
7. Test different encodings: `..%2f..%2f..%2fetc%2fpasswd`
8. Test null byte injection (legacy): `../../../etc/passwd%00.png`
9. Check for XXE in XML/SOAP endpoints
10. Verify successful retrieval by identifying passwd file format in response

### Key Payloads
- `/etc/passwd`
- `../../../etc/passwd`
- `....//....//....//etc/passwd`
- `..%2f..%2f..%2fetc%2fpasswd`
- `/etc/passwd%00.jpg`
- `file:///etc/passwd`

### Indicators of Success
- Response contains `/etc/passwd` content
- Lines matching format: `root:x:0:0:root:/root:/bin/bash`
- Multiple user entries with colon-separated fields
- File path manipulation reflects in response
- No "file not found" or sanitization errors

---
*Source: PortSwigger Web Security Academy*
