## Insecure direct object references

**Category:** broken_access_control
**Difficulty:** Unknown

### Description
This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

### Solution Steps
1. Select the Live chat tab.
2. Send a message and then select View transcript .
3. Review the URL and observe that the transcripts are text files assigned a filename containing an incrementing number.
4. Change the filename to 1.txt and review the text. Notice a password within the chat transcript.
5. Return to the main lab page and log in using the stolen credentials.

### Key Payloads
- `carlos`
- `1.txt`

### Indicators of Success
- Unauthorized resource accessed
- Other user's data visible
- Admin functionality available to regular user
- IDOR allows accessing other records
- Horizontal/vertical privilege escalation
---
*Source: PortSwigger Web Security Academy*
