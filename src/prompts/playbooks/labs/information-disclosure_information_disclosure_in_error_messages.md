## Information disclosure in error messages

**Category:** info_disclosure
**Difficulty:** Unknown

### Description
This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

### Solution Steps
1. With Burp running, open one of the product pages.
2. In Burp, go to "Proxy" > "HTTP history" and notice that the GET request for product pages contains a productID parameter. Send the GET /product?productId=1 request to Burp Repeater. Note that your productId might be different depending on which product page you loaded.
3. In Burp Repeater, change the value of the productId parameter to a non-integer data type, such as a string. Send the request: GET /product?productId="example"
4. The unexpected data type causes an exception, and a full stack trace is displayed in the response. This reveals that the lab is using Apache Struts 2 2.3.31.
5. Go back to the lab, click "Submit solution", and enter 2 2.3.31 to solve the lab.

### Key Payloads
- `productID`
- `GET /product?productId=1`
- `productId`
- `GET /product?productId="example"`

### Indicators of Success
- Sensitive data exposed in response
- Error messages reveal internal details
- Debug endpoints accessible
- Source code or credentials leaked
- Stack traces or version info visible
---
*Source: PortSwigger Web Security Academy*
