## Bypassing rate limits via race conditions

**Category:** race_condition
**Difficulty:** Unknown

### Description
This lab's login mechanism uses rate limiting to defend against brute-force attacks. However, this can be bypassed due to a race condition.

### Solution Steps
123123
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
1234567890
michael
x654321
superman
1qaz2wsx
baseball
7777777
121212
000000

### Key Payloads
- `carlos`
- `wiener:peter`
- `123123
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
1234567890
michael
x654321
superman
1qaz2wsx
baseball
7777777
121212
000000`
- `Invalid username or password`
- `POST /login`
- `Invalid username and password`
- `password`
- `username`
- `examples/race-single-packet-attack.py`
- `wordlists.clipboard`

### Indicators of Success
- Concurrent requests bypass rate limits
- Duplicate transactions or actions occur
- TOCTOU (time-of-check-time-of-use) exploited
- Business constraints violated via timing
- Resource limits exceeded through parallelism
---
*Source: PortSwigger Web Security Academy*
