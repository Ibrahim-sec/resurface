## Limit overrun race conditions

**Category:** race_condition
**Difficulty:** Unknown

### Description
This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

### Solution Steps
1. Log in and buy the cheapest item possible, making sure to use the provided discount code so that you can study the purchasing flow.
2. Consider that the shopping cart mechanism and, in particular, the restrictions that determine what you are allowed to order, are worth trying to bypass.
3. In Burp, from the proxy history, identify all endpoints that enable you to interact with the cart. For example, a POST /cart request adds items to the cart and a POST /cart/coupon request applies the discount code.
4. Try to identify any restrictions that are in place on these endpoints. For example, observe that if you try applying the discount code more than once, you receive a Coupon already applied response.
5. Make sure you have an item to your cart, then send the GET /cart request to Burp Repeater.
6. In Repeater, try sending the GET /cart request both with and without your session cookie. Confirm that without the session cookie, you can only access an empty cart. From this, you can infer that: The state of the cart is stored server-side in your session. Any operations on the cart are keyed on your session ID or the associated user ID. This indicates that there is potential for a collision.
7. Consider that there may be a race window between when you first apply a discount code and when the database is updated to reflect that you've done this already.

### Key Payloads
- `wiener:peter`
- `POST /cart`
- `POST /cart/coupon`
- `Coupon already applied`
- `GET /cart`

### Indicators of Success
- Concurrent requests bypass rate limits
- Duplicate transactions or actions occur
- TOCTOU (time-of-check-time-of-use) exploited
- Business constraints violated via timing
- Resource limits exceeded through parallelism
---
*Source: PortSwigger Web Security Academy*
