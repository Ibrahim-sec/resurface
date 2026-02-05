## Developing a custom gadget chain for PHP deserialization

**Category:** deserialization
**Difficulty:** Unknown

### Description
This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its insecure deserialization to achieve remote code execution. To solve the lab, delete themorale.txtfile from Carlos's home directory.

### Solution Steps
You can sometimes read source code by appending a tilde (
~
) to a filename to retrieve an editor-generated backup file.

### Key Payloads
- `morale.txt`
- `wiener:peter`
- `/cgi-bin/libs/CustomTemplate.php`
- `.php~`
- `__wakeup()`
- `CustomTemplate`
- `Product`
- `default_desc_type`
- `desc`
- `DefaultMap`

### Indicators of Success
- Serialized payload processed without error
- Code execution via gadget chain
- File created/deleted on server
- Out-of-band callback received
- Server behavior indicates deserialization
---
*Source: PortSwigger Web Security Academy*
