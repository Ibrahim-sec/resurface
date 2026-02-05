## Low-level logic flaw

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

### Solution Steps
You will need to use Burp Intruder (or Turbo Intruder) to solve this lab.
To make sure the price increases in predictable increments, we recommend configuring your attack to only send one request at a time. In Burp Intruder, you can do this from the resource pool settings using the
Maximum concurrent requests
option.

### Key Payloads
- `wiener:peter`
- `POST /cart`
- `quantity`
- `-$1221.96`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: logic_flaw

---
*Source: PortSwigger Web Security Academy*
