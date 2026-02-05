## Flawed enforcement of business rules

**Category:** logic_flaw
**Difficulty:** Unknown

### Description
This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

### Solution Steps
1. Log in and notice that there is a coupon code, NEWCUST5 .
2. At the bottom of the page, sign up to the newsletter. You receive another coupon code, SIGNUP30 .
3. Add the leather jacket to your cart.
4. Go to the checkout and apply both of the coupon codes to get a discount on your order.
5. Try applying the codes more than once. Notice that if you enter the same code twice in a row, it is rejected because the coupon has already been applied. However, if you alternate between the two codes, you can bypass this control.
6. Reuse the two codes enough times to reduce your order total to less than your remaining store credit. Complete the order to solve the lab.

### Key Payloads
- `wiener:peter`
- `NEWCUST5`
- `SIGNUP30`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: logic_flaw

---
*Source: PortSwigger Web Security Academy*
