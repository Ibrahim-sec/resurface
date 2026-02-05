## Information disclosure on debug page

**Category:** info_disclosure
**Difficulty:** Unknown

### Description
This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit theSECRET_KEYenvironment variable.

### Solution Steps
1. With Burp running, browse to the home page.
2. Go to the "Target" > "Site Map" tab. Right-click on the top-level entry for the lab and select "Engagement tools" > "Find comments". Notice that the home page contains an HTML comment that contains a link called "Debug". This points to /cgi-bin/phpinfo.php .
3. In the site map, right-click on the entry for /cgi-bin/phpinfo.php and select "Send to Repeater".
4. In Burp Repeater, send the request to retrieve the file. Notice that it reveals various debugging information, including the SECRET_KEY environment variable.
5. Go back to the lab, click "Submit solution", and enter the SECRET_KEY to solve the lab.

### Key Payloads
- `SECRET_KEY`
- `/cgi-bin/phpinfo.php`

### Indicators of Success
- Sensitive data exposed in response
- Error messages reveal internal details
- Debug endpoints accessible
- Source code or credentials leaked
- Stack traces or version info visible
---
*Source: PortSwigger Web Security Academy*
