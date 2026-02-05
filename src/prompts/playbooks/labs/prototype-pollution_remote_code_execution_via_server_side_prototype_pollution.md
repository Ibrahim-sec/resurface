## Remote code execution via server-side prototype pollution

**Category:** prototype_pollution
**Difficulty:** Unknown

### Description
This lab is built on Node.js and the Express framework. It is vulnerable to server-side prototype pollution because it unsafely merges user-controllable input into a server-side JavaScript object.

### Solution Steps
The command execution sink is only invoked when an admin user triggers vulnerable functionality on the site.

### Key Payloads
- `Object.prototype`
- `/home/carlos/morale.txt`
- `wiener:peter`
- `POST /my-account/change-address`
- `__proto__`
- `json spaces`
- `"__proto__": {
    "json spaces":10
}`
- `execArgv`
- `--eval`
- `execSync()`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: prototype_pollution

---
*Source: PortSwigger Web Security Academy*
