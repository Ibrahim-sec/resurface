## Infinite money logic flaw

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

### Solution Steps
1. With Burp running, log in and sign up for the newsletter to obtain a coupon code, SIGNUP30 . Notice that you can buy $10 gift cards and redeem them from the My account page.
2. Add a gift card to your basket and proceed to the checkout. Apply the coupon code to get a 30% discount. Complete the order and copy the gift card code to your clipboard.
3. Go to your account page and redeem the gift card. Observe that this entire process has added $3 to your store credit. Now you need to try and automate this process.
4. Study the proxy history and notice that you redeem your gift card by supplying the code in the gift-card parameter of the POST /gift-card request.
5. Click Settings in the top toolbar. The Settings dialog opens.
6. Click Sessions . In the Session handling rules panel, click Add . The Session handling rule editor dialog opens.
7. In the dialog, go to the Scope tab. Under URL scope , select Include all URLs .
8. Go back to the Details tab. Under Rule actions , click Add > Run a macro . Under Select macro , click Add again to open the Macro Recorder .
9. Select the following sequence of requests: POST /cart
POST /cart/coupon
POST /cart/checkout
GET /cart/order-confirmation?order-confirmed=true
POST /gift-card Then, click OK . The Macro Editor opens.
10. In the list of requests, select GET /cart/order-confirmation?order-confirmed=true . Click Configure item . In the dialog that opens, click Add to create a custom parameter. Name the parameter gift-card and highlight the gift card code at the bottom of the response. Click OK twice to go back to the Macro Editor .
11. Select the POST /gift-card request and click Configure item again. In the Parameter handling section, use the drop-down menus to specify that the gift-card parameter should be derived from the prior response (response 4). Click OK .
12. In the Macro Editor , click Test macro . Look at the response to GET /cart/order-confirmation?order-confirmation=true and note the gift card code that was generated. Look at the POST /gift-card request. Make sure that the gift-card parameter matches and confirm that it received a 302 response. Keep clicking OK until you get back to the main Burp window.
13. Send the GET /my-account request to Burp Intruder. Make sure that Sniper attack is selected.
14. In the Payloads side panel, under Payload configuration , select the payload type Null payloads . Choose to generate 412 payloads.
15. Click on Resource pool to open the Resource pool side panel. Add the attack to a resource pool with the Maximum concurrent requests set to 1 . Start the attack.
16. When the attack finishes, you will have enough store credit to buy the jacket and solve the lab.

### Key Payloads
- `wiener:peter`
- `SIGNUP30`
- `gift-card`
- `POST /gift-card`
- `POST /cart
POST /cart/coupon
POST /cart/checkout
GET /cart/order-confirmation?order-confirmed=true
POST /gift-card`
- `GET /cart/order-confirmation?order-confirmed=true`
- `GET /cart/order-confirmation?order-confirmation=true`
- `GET /my-account`

### Indicators of Success
- Business logic bypassed or manipulated
- Workflow steps skipped or reordered
- Price/quantity manipulation successful
- Negative or extreme values accepted
- State machine or validation violated
---
*Source: PortSwigger Web Security Academy*
