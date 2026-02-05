## Accidental exposure of private GraphQL fields

**Category:** graphql
**Difficulty:** Unknown

### Description
The user management functions for this lab are powered by a GraphQL endpoint. The lab contains an access control vulnerability whereby you can induce the API to reveal user credential fields.

### Solution Steps
1. In Burp's browser, access the lab and select My account .
2. Attempt to log in to the site.
3. In Burp, go to Proxy > HTTP history and notice that the login attempt is sent as a GraphQL mutation containing a username and password.
4. Right-click the login request and select Send to Repeater .
5. In Repeater, right-click anywhere within the Request panel of the message editor and select GraphQL > Set introspection query to insert an introspection query into the request body.
6. Send the request.
7. Right-click the message and select GraphQL > Save GraphQL queries to site map .
8. Go to Target > Site map and review the GraphQL queries. Notice the following: There is a getUser query that returns a user's username and password. This query fetches the relevant user information via a direct reference to an id number.

### Key Payloads
- `carlos`
- `getUser`

### Indicators of Success
- Introspection query returns schema
- Hidden fields/queries discovered
- Authorization bypass via GraphQL
- Batching bypasses rate limits
- Sensitive data exposed via queries
---
*Source: PortSwigger Web Security Academy*
