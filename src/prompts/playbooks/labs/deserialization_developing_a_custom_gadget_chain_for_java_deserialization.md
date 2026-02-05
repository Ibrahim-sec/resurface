## Developing a custom gadget chain for Java deserialization

**Category:** deserialization
**Difficulty:** Unknown

### Description
This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's insecure deserialization to obtain the administrator's password.

### Solution Steps
To save you some of the effort, we've provided a
generic Java program for serializing objects
. You can adapt this to generate a suitable object for your exploit. If you don't already have a Java environment set up, you can compile and execute the program using a browser-based IDE, such as
repl.it
.

### Key Payloads
- `administrator`
- `carlos`
- `wiener:peter`
- `repl.it`
- `/backup/AccessTokenUser.java`
- `/backup`
- `ProductTemplate.java`
- `ProductTemplate.readObject()`
- `ProductTemplate`
- `"your-payload-here"`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: deserialization

---
*Source: PortSwigger Web Security Academy*
