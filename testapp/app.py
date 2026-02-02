"""
Resurface Test App — Comprehensive Intentionally Vulnerable Web Application
DO NOT expose this to the internet. For testing/demo only.

Vulnerability classes:
  VULNERABLE (should be detected as VULNERABLE):
    /search?q=             — Reflected XSS (no sanitization)
    /profile/<id>          — IDOR (returns any user's data)
    /redirect?url=         — Open redirect (no validation)
    /api/user/<id>         — IDOR via API (JSON)
    /fetch?url=            — SSRF (fetches arbitrary URLs)
    /read?file=            — Path traversal (reads files)
    /comment               — Stored XSS (POST stores, GET renders)
    /admin/debug           — Info disclosure (dumps env/config)

  FIXED (should be detected as FIXED):
    /search-safe?q=        — XSS with HTML escaping
    /profile-safe/<id>     — IDOR with session auth check
    /redirect-safe?url=    — Redirect with domain whitelist
    /api/user-safe/<id>    — IDOR with proper authorization

  PARTIALLY FIXED (should be detected as PARTIAL):
    /search-partial?q=     — XSS with <script> filter (bypassable)
    /redirect-partial?url= — Redirect blocking http:// but not //evil.com
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, urlencode
import json
import html
import os
import re
import urllib.request
import urllib.error

# ──────────────────────────────────────────────
#  Fake data stores
# ──────────────────────────────────────────────

USERS = {
    "1": {"id": 1, "name": "Alice Admin", "email": "alice@company.com", "role": "admin", "ssn": "123-45-6789"},
    "2": {"id": 2, "name": "Bob User", "email": "bob@company.com", "role": "user", "ssn": "987-65-4321"},
    "3": {"id": 3, "name": "Charlie Test", "email": "charlie@company.com", "role": "user", "ssn": "555-12-3456"},
    "4": {"id": 4, "name": "Dana Manager", "email": "dana@company.com", "role": "manager", "ssn": "111-22-3333"},
    "5": {"id": 5, "name": "Eve Security", "email": "eve@company.com", "role": "security", "ssn": "444-55-6666"},
}

COMMENTS = [
    {"user": "Alice", "text": "Welcome to the platform!"},
    {"user": "Bob", "text": "Great product, love it."},
]

CONFIG_SECRETS = {
    "db_host": "internal-db.company.local",
    "db_password": "super_secret_p4ssw0rd!",
    "api_key": "sk-live-abc123def456ghi789",
    "aws_secret": "AKIAIOSFODNN7EXAMPLE",
    "jwt_secret": "my-jwt-signing-secret-2025",
    "stripe_key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
}

# Allowed redirect domains (for safe version)
ALLOWED_REDIRECT_DOMAINS = ["example.com", "company.com", "safe.local"]

# Simulated session (for safe endpoints)
CURRENT_SESSION_USER_ID = "2"  # Bob is "logged in"

STYLE = """
body{font-family:sans-serif;max-width:900px;margin:40px auto;background:#0d1117;color:#e6edf3;padding:0 20px}
a{color:#58a6ff}h1,h2,h3{color:#c9a0ff}
code{background:#161b22;padding:2px 6px;border-radius:3px;color:#ff7b72}
.card{background:#161b22;padding:15px;margin:10px 0;border-radius:8px;border-left:3px solid #ff4444}
.safe{border-left-color:#3fb950}
.partial{border-left-color:#d29922}
input,textarea{padding:8px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:5px}
button{padding:8px 20px;background:#7b2ff7;color:white;border:none;border-radius:5px;cursor:pointer}
button:hover{background:#6e26d9}
pre{background:#161b22;padding:12px;border-radius:5px;overflow-x:auto}
"""


class VulnerableHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Quiet logging

    def _send(self, code, content, content_type="text/html"):
        if isinstance(content, str):
            content = content.encode('utf-8')
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, code, data):
        self._send(code, json.dumps(data, indent=2), "application/json")

    def _html_page(self, title, body_html):
        return f"""<!DOCTYPE html>
<html><head><title>{html.escape(title)} — Resurface Testapp</title>
<style>{STYLE}</style></head>
<body>
<h1>🔄 Resurface Test App</h1>
<p style="color:#8b949e"><a href="/">← Home</a></p>
{body_html}
</body></html>"""

    # ─────────────── Routing ───────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        params = parse_qs(parsed.query)

        routes = {
            '':                 self._home,
            '/health':          self._health,
            # VULNERABLE
            '/search':          self._search_vuln,
            '/profile':         self._profile_vuln,
            '/redirect':        self._redirect_vuln,
            '/api/user':        self._api_user_vuln,
            '/fetch':           self._fetch_vuln,
            '/read':            self._read_vuln,
            '/comment':         self._comment_get,
            '/admin/debug':     self._admin_debug,
            # FIXED
            '/search-safe':     self._search_safe,
            '/profile-safe':    self._profile_safe,
            '/redirect-safe':   self._redirect_safe,
            '/api/user-safe':   self._api_user_safe,
            # PARTIAL
            '/search-partial':  self._search_partial,
            '/redirect-partial': self._redirect_partial,
        }

        # Check for path-parameter style routes: /profile/<id>, /api/user/<id>
        if path.startswith('/profile/') and not path.startswith('/profile-safe/'):
            return self._profile_vuln_path(path, params)
        if path.startswith('/profile-safe/'):
            return self._profile_safe_path(path, params)
        if path.startswith('/api/user/') and not path.startswith('/api/user-safe/'):
            return self._api_user_vuln_path(path, params)
        if path.startswith('/api/user-safe/'):
            return self._api_user_safe_path(path, params)

        handler = routes.get(path)
        if handler:
            handler(params)
        else:
            self._send(404, self._html_page("404", "<h2>404 — Not Found</h2>"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace') if content_length else ""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        params = parse_qs(body)

        if path == '/comment':
            self._comment_post(params)
        else:
            self._send(404, self._html_page("404", "<h2>404 — Not Found</h2>"))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  HOME + HEALTH
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _home(self, params):
        body = """
        <p>⚠️ Intentionally vulnerable. For testing only.</p>
        <h2 style="color:#ff4444">🔴 Vulnerable Endpoints</h2>

        <div class="card">
            <h3>1. Reflected XSS</h3>
            <code>GET /search?q=&lt;script&gt;alert(1)&lt;/script&gt;</code>
        </div>
        <div class="card">
            <h3>2. IDOR — User Profile</h3>
            <code>GET /profile/1</code> — or <code>/profile?id=1</code>
        </div>
        <div class="card">
            <h3>3. Open Redirect</h3>
            <code>GET /redirect?url=https://evil.com</code>
        </div>
        <div class="card">
            <h3>4. IDOR — API</h3>
            <code>GET /api/user/1</code> — or <code>/api/user?id=1</code>
        </div>
        <div class="card">
            <h3>5. SSRF</h3>
            <code>GET /fetch?url=http://169.254.169.254/latest/meta-data/</code>
        </div>
        <div class="card">
            <h3>6. Path Traversal</h3>
            <code>GET /read?file=../../etc/passwd</code>
        </div>
        <div class="card">
            <h3>7. Stored XSS</h3>
            <code>POST /comment</code> then <code>GET /comment</code>
        </div>
        <div class="card">
            <h3>8. Info Disclosure</h3>
            <code>GET /admin/debug</code>
        </div>

        <h2 style="color:#3fb950">🟢 Fixed Endpoints</h2>
        <div class="card safe">
            <h3>1. XSS — Safe Search</h3>
            <code>GET /search-safe?q=&lt;script&gt;alert(1)&lt;/script&gt;</code>
        </div>
        <div class="card safe">
            <h3>2. IDOR — Safe Profile</h3>
            <code>GET /profile-safe/1</code>
        </div>
        <div class="card safe">
            <h3>3. Redirect — Safe</h3>
            <code>GET /redirect-safe?url=https://evil.com</code>
        </div>
        <div class="card safe">
            <h3>4. IDOR — Safe API</h3>
            <code>GET /api/user-safe/1</code>
        </div>

        <h2 style="color:#d29922">🟡 Partially Fixed</h2>
        <div class="card partial">
            <h3>1. XSS — Partial Filter</h3>
            <code>GET /search-partial?q=&lt;img src=x onerror=alert(1)&gt;</code>
        </div>
        <div class="card partial">
            <h3>2. Redirect — Partial Block</h3>
            <code>GET /redirect-partial?url=//evil.com</code>
        </div>
        """
        self._send(200, self._html_page("Home", body))

    def _health(self, params):
        self._send_json(200, {"status": "ok", "endpoints": 16})

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  VULNERABLE ENDPOINTS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    # --- 1. Reflected XSS ---
    def _search_vuln(self, params):
        query = params.get("q", [""])[0]
        # VULNERABLE: No sanitization — reflects input directly into HTML
        body = f"""
        <h2>Search Results</h2>
        <p>Results for: {query}</p>
        <p>No results found for "{query}"</p>
        <form method="GET" action="/search">
            <input name="q" value="{query}" style="width:300px"> <button type="submit">Search</button>
        </form>"""
        self._send(200, self._html_page("Search", body))

    # --- 2. IDOR — Profile (query param) ---
    def _profile_vuln(self, params):
        user_id = params.get("id", [""])[0]
        user = USERS.get(user_id)
        if user:
            body = f"""
            <h2>User Profile</h2>
            <pre>{json.dumps(user, indent=2)}</pre>"""
            self._send(200, self._html_page("Profile", body))
        else:
            self._send(404, self._html_page("Profile", "<h2>User not found</h2>"))

    # --- 2b. IDOR — Profile (path param) ---
    def _profile_vuln_path(self, path, params):
        user_id = path.split('/')[-1]
        user = USERS.get(user_id)
        if user:
            # VULNERABLE: No auth check — any user's data returned
            self._send(200, self._html_page("Profile",
                f"<h2>User Profile</h2><pre>{json.dumps(user, indent=2)}</pre>"))
        else:
            self._send(404, self._html_page("Profile", "<h2>User not found</h2>"))

    # --- 3. Open Redirect ---
    def _redirect_vuln(self, params):
        url = params.get("url", [""])[0]
        if url:
            # VULNERABLE: No validation on redirect target
            self.send_response(302)
            self.send_header("Location", url)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(400, self._html_page("Redirect", "<h2>Missing url parameter</h2>"))

    # --- 4. IDOR — API (query param) ---
    def _api_user_vuln(self, params):
        user_id = params.get("id", [""])[0]
        user = USERS.get(user_id)
        if user:
            # VULNERABLE: No authorization check
            self._send_json(200, user)
        else:
            self._send_json(404, {"error": "User not found"})

    # --- 4b. IDOR — API (path param) ---
    def _api_user_vuln_path(self, path, params):
        user_id = path.split('/')[-1]
        user = USERS.get(user_id)
        if user:
            # VULNERABLE: No authorization check — exposes PII
            self._send_json(200, user)
        else:
            self._send_json(404, {"error": "User not found"})

    # --- 5. SSRF ---
    def _fetch_vuln(self, params):
        target_url = params.get("url", [""])[0]
        if not target_url:
            self._send(400, self._html_page("Fetch", "<h2>Missing url parameter</h2>"))
            return
        # VULNERABLE: Fetches arbitrary URLs server-side
        try:
            req = urllib.request.Request(target_url, headers={
                'User-Agent': 'Resurface-Testapp/1.0'
            })
            resp = urllib.request.urlopen(req, timeout=5)
            content = resp.read().decode('utf-8', errors='replace')[:10000]
            body = f"""
            <h2>Fetched URL</h2>
            <p>URL: <code>{html.escape(target_url)}</code></p>
            <p>Status: {resp.status}</p>
            <pre>{html.escape(content)}</pre>"""
            self._send(200, self._html_page("Fetch", body))
        except Exception as e:
            self._send(500, self._html_page("Fetch",
                f"<h2>Fetch Error</h2><pre>{html.escape(str(e))}</pre>"))

    # --- 6. Path Traversal ---
    def _read_vuln(self, params):
        filename = params.get("file", [""])[0]
        if not filename:
            self._send(400, self._html_page("Read", "<h2>Missing file parameter</h2>"))
            return
        # VULNERABLE: No path sanitization — directory traversal possible
        base_dir = os.path.join(os.path.dirname(__file__), "files")
        filepath = os.path.join(base_dir, filename)
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            body = f"""
            <h2>File Contents</h2>
            <p>File: <code>{html.escape(filename)}</code></p>
            <pre>{html.escape(content)}</pre>"""
            self._send(200, self._html_page("Read", body))
        except FileNotFoundError:
            self._send(404, self._html_page("Read",
                f"<h2>File not found: {html.escape(filename)}</h2>"))
        except Exception as e:
            self._send(500, self._html_page("Read",
                f"<h2>Error: {html.escape(str(e))}</h2>"))

    # --- 7. Stored XSS — GET (view comments) ---
    def _comment_get(self, params):
        comments_html = ""
        for c in COMMENTS:
            # VULNERABLE: Renders unsanitized stored input
            comments_html += (
                f"<div style='background:#161b22;padding:10px;margin:5px 0;border-radius:5px'>"
                f"<b>{c['user']}</b>: {c['text']}</div>"
            )
        body = f"""
        <h2>Comments</h2>
        {comments_html}
        <h3>Add Comment</h3>
        <form method="POST" action="/comment">
            <input name="user" placeholder="Name" style="width:200px"><br><br>
            <textarea name="text" placeholder="Comment" style="width:400px;height:80px"></textarea><br><br>
            <button type="submit">Post Comment</button>
        </form>"""
        self._send(200, self._html_page("Comments", body))

    # --- 7b. Stored XSS — POST (store comment) ---
    def _comment_post(self, params):
        user = params.get("user", ["Anonymous"])[0]
        text = params.get("text", [""])[0]
        # VULNERABLE: Stores unsanitized input
        COMMENTS.append({"user": user, "text": text})
        self.send_response(302)
        self.send_header("Location", "/comment")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # --- 8. Info Disclosure ---
    def _admin_debug(self, params):
        # VULNERABLE: Exposes secrets, env vars, and config
        env_vars = {k: v for k, v in os.environ.items()
                    if not k.startswith('_')}
        debug_data = {
            "config": CONFIG_SECRETS,
            "environment": dict(list(env_vars.items())[:30]),
            "users_count": len(USERS),
            "server_info": {
                "python": os.sys.version,
                "pid": os.getpid(),
                "cwd": os.getcwd(),
            }
        }
        self._send_json(200, debug_data)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  FIXED ENDPOINTS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    # --- 1. XSS — Safe Search ---
    def _search_safe(self, params):
        query = params.get("q", [""])[0]
        # FIXED: Proper HTML escaping
        safe_query = html.escape(query)
        body = f"""
        <h2>Search Results (Safe)</h2>
        <p>Results for: {safe_query}</p>
        <p>No results found for "{safe_query}"</p>
        <form method="GET" action="/search-safe">
            <input name="q" value="{safe_query}" style="width:300px"> <button type="submit">Search</button>
        </form>"""
        self._send(200, self._html_page("Safe Search", body))

    # --- 2. IDOR — Safe Profile ---
    def _profile_safe(self, params):
        user_id = params.get("id", [""])[0]
        self._do_profile_safe(user_id)

    def _profile_safe_path(self, path, params):
        user_id = path.split('/')[-1]
        self._do_profile_safe(user_id)

    def _do_profile_safe(self, user_id):
        # FIXED: Only allow access to own profile (session check)
        if user_id != CURRENT_SESSION_USER_ID:
            self._send_json(403, {
                "error": "Forbidden",
                "message": "You can only access your own profile"
            })
            return
        user = USERS.get(user_id)
        if user:
            # Return safe subset — no SSN
            safe_user = {k: v for k, v in user.items() if k != 'ssn'}
            self._send_json(200, safe_user)
        else:
            self._send_json(404, {"error": "User not found"})

    # --- 3. Redirect — Safe ---
    def _redirect_safe(self, params):
        url = params.get("url", [""])[0]
        if not url:
            self._send(400, self._html_page("Redirect", "<h2>Missing url parameter</h2>"))
            return
        # FIXED: Only allow redirects to whitelisted domains
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain and domain not in ALLOWED_REDIRECT_DOMAINS:
                self._send(403, self._html_page("Redirect",
                    f"<h2>Redirect blocked</h2><p>Domain <code>{html.escape(domain)}</code> "
                    f"is not in the allow list.</p>"))
                return
            self.send_response(302)
            self.send_header("Location", url)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            self._send(400, self._html_page("Redirect", "<h2>Invalid URL</h2>"))

    # --- 4. IDOR — Safe API ---
    def _api_user_safe(self, params):
        user_id = params.get("id", [""])[0]
        self._do_api_user_safe(user_id)

    def _api_user_safe_path(self, path, params):
        user_id = path.split('/')[-1]
        self._do_api_user_safe(user_id)

    def _do_api_user_safe(self, user_id):
        # FIXED: Proper authorization — only own data
        if user_id != CURRENT_SESSION_USER_ID:
            self._send_json(403, {
                "error": "Forbidden",
                "message": "You are not authorized to view this user's data"
            })
            return
        user = USERS.get(user_id)
        if user:
            safe_user = {k: v for k, v in user.items() if k != 'ssn'}
            self._send_json(200, safe_user)
        else:
            self._send_json(404, {"error": "User not found"})

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  PARTIALLY FIXED ENDPOINTS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    # --- 1. XSS — Partial (script tag filter only) ---
    def _search_partial(self, params):
        query = params.get("q", [""])[0]
        # PARTIAL FIX: Removes <script> tags but misses event handlers
        # Bypassable with: <img src=x onerror=alert(1)>
        filtered = re.sub(r'<script[^>]*>.*?</script>', '', query, flags=re.IGNORECASE | re.DOTALL)
        filtered = re.sub(r'<script[^>]*>', '', filtered, flags=re.IGNORECASE)
        filtered = re.sub(r'</script>', '', filtered, flags=re.IGNORECASE)
        body = f"""
        <h2>Search Results (Filtered)</h2>
        <p>Results for: {filtered}</p>
        <p>No results found for "{filtered}"</p>
        <p style="color:#8b949e">Note: &lt;script&gt; tags are filtered</p>
        <form method="GET" action="/search-partial">
            <input name="q" value="" style="width:300px"> <button type="submit">Search</button>
        </form>"""
        self._send(200, self._html_page("Partial Search", body))

    # --- 2. Redirect — Partial (blocks http:// but not protocol-relative) ---
    def _redirect_partial(self, params):
        url = params.get("url", [""])[0]
        if not url:
            self._send(400, self._html_page("Redirect", "<h2>Missing url parameter</h2>"))
            return
        # PARTIAL FIX: Blocks http:// and https:// external but not //evil.com
        if url.lower().startswith('http://') or url.lower().startswith('https://'):
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc not in ALLOWED_REDIRECT_DOMAINS:
                self._send(403, self._html_page("Redirect",
                    f"<h2>Redirect blocked</h2>"
                    f"<p>External URLs with http/https are not allowed.</p>"))
                return
        # Protocol-relative URLs like //evil.com slip through
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    port = int(os.environ.get('TESTAPP_PORT', '9999'))
    host = os.environ.get('TESTAPP_HOST', '127.0.0.1')
    server = HTTPServer((host, port), VulnerableHandler)
    print(f"🎯 Resurface Test App running on http://{host}:{port}")
    print(f"   ⚠️  Intentionally vulnerable — do NOT expose to the internet")
    print(f"   Endpoints: 8 vulnerable, 4 fixed, 2 partially fixed")
    print(f"   Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
