## Blind OS command injection with output redirection

**Category:** rce
**Difficulty:** Unknown

### Description
This lab contains a blind OS command injection vulnerability in the feedback function.

### Solution Steps
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the email parameter, changing it to: email=||whoami>/var/www/images/output.txt||
3. Now use Burp Suite to intercept and modify the request that loads an image of a product.
4. Modify the filename parameter, changing the value to the name of the file you specified for the output of the injected command: filename=output.txt
5. Observe that the response contains the output from the injected command.

### Key Payloads
- `/var/www/images/`
- `whoami`
- `email`
- `email=||whoami>/var/www/images/output.txt||`
- `filename`
- `filename=output.txt`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: rce

---
*Source: PortSwigger Web Security Academy*
