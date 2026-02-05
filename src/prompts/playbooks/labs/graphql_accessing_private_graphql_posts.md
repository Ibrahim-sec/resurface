## Accessing private GraphQL posts

**Category:** graphql
**Difficulty:** Unknown

### Description
The blog page for this lab contains a hidden blog post that has a secret password. To solve the lab, find the hidden blog post and enter the password.

### Solution Steps
1. In Burp's browser, access the blog page.
2. In Burp, go to Proxy > HTTP history and notice the following: Blog posts are retrieved using a GraphQL query. In the response to the GraphQL query, each blog post has its own sequential id . Blog post id 3 is missing from the list. This indicates that there is a hidden blog post.
3. Find the POST /graphql/v1 request. Right-click it and select Send to Repeater .
4. In Repeater, right-click anywhere in the Request panel of the message editor and select GraphQL > Set introspection query to insert an introspection query into the request body.
5. Send the request. Notice in the response that the BlogPost type has a postPassword field available.

### Key Payloads
- `POST /graphql/v1`
- `BlogPost`
- `postPassword`

### Indicators of Success
- Introspection query returns schema
- Hidden fields/queries discovered
- Authorization bypass via GraphQL
- Batching bypasses rate limits
- Sensitive data exposed via queries
---
*Source: PortSwigger Web Security Academy*
