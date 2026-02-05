## Server-side template injection with information disclosure via user-supplied objects

**Category:** ssti
**Difficulty:** Unknown

### Description
This lab is vulnerable to server-side template injection due to the way an object is being passed into the template. This vulnerability can be exploited to access sensitive data.

### Solution Steps
1. Log in and edit one of the product description templates.
2. Change one of the template expressions to something invalid, such as a fuzz string ${{<%[%'"}}%\ , and save the template. The error message in the output hints that the Django framework is being used.
3. Study the Django documentation and notice that the built-in template tag debug can be called to display debugging information.
4. In the template, remove your invalid syntax and enter the following statement to invoke the debug built-in: {% debug %}
5. Save the template. The output will contain a list of objects and properties to which you have access from within this template. Crucially, notice that you can access the settings object.
6. Study the settings object in the Django documentation and notice that it contains a SECRET_KEY property, which has dangerous security implications if known to an attacker.
7. In the template, remove the {% debug %} statement and enter the expression {{settings.SECRET_KEY}}
8. Save the template to output the framework's secret key.
9. Click the "Submit solution" button and submit the secret key to solve the lab.

### Key Payloads
- `content-manager:C0nt3ntM4n4g3r`
- `${{<%[%'"}}%\`
- `debug`
- `{% debug %}`
- `settings`
- `SECRET_KEY`
- `{{settings.SECRET_KEY}}`

### Indicators of Success
- Template expression evaluated (7*7=49)
- Server-side code execution confirmed
- OS command output visible
- Template engine identified
- File read/write or RCE achieved
---
*Source: PortSwigger Web Security Academy*
