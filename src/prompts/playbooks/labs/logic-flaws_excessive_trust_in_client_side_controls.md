## Excessive trust in client-side controls

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

### Solution Steps
1. With Burp running, log in and attempt to buy the leather jacket. The order is rejected because you don't have enough store credit.
2. In Burp, go to "Proxy" > "HTTP history" and study the order process. Notice that when you add an item to your cart, the corresponding request contains a price parameter. Send the POST /cart request to Burp Repeater.
3. In Burp Repeater, change the price to an arbitrary integer and send the request. Refresh the cart and confirm that the price has changed based on your input.
4. Repeat this process to set the price to any amount less than your available store credit.
5. Complete the order to solve the lab.

### Key Payloads
- `wiener:peter`
- `price`
- `POST /cart`

### Indicators of Success
- Business logic bypassed or manipulated
- Workflow steps skipped or reordered
- Price/quantity manipulation successful
- Negative or extreme values accepted
- State machine or validation violated
---
*Source: PortSwigger Web Security Academy*
