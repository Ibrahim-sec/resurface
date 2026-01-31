"""
Resurface Test App — Intentionally Vulnerable Web Application
DO NOT expose this to the internet. For testing/demo only.

Contains realistic vulnerabilities matching common HackerOne report types:
- Reflected XSS
- Stored XSS  
- IDOR (Insecure Direct Object Reference)
- Open Redirect
- Path Traversal
- Information Disclosure
- CSRF (no token validation)
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import json
import html
import os

# Fake user database
USERS = {
    "1": {"id": 1, "name": "Alice Admin", "email": "alice@company.com", "role": "admin", "ssn": "123-45-6789"},
    "2": {"id": 2, "name": "Bob User", "email": "bob@company.com", "role": "user", "ssn": "987-65-4321"},
    "3": {"id": 3, "name": "Charlie Test", "email": "charlie@company.com", "role": "user", "ssn": "555-12-3456"},
}

# Stored XSS comments
COMMENTS = [
    {"user": "Alice", "text": "Welcome to the platform!"},
    {"user": "Bob", "text": "Great product, love it."},
]

# Fake API keys (info disclosure)
CONFIG = {
    "db_host": "internal-db.company.local",
    "db_password": "super_secret_p4ssw0rd!",
    "api_key": "sk-live-abc123def456ghi789",
    "aws_secret": "AKIAIOSFODNN7EXAMPLE",
}


class VulnerableHandler(BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        pass  # Quiet logging
    
    def _send(self, code, content, content_type="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        # Intentionally no CSP, no X-Frame-Options, etc.
        self.end_headers()
        self.wfile.write(content.encode())
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        # === HOME PAGE ===
        if path == "/" or path == "":
            self._send(200, """
            <html><head><title>Resurface Test App</title>
            <style>body{font-family:sans-serif;max-width:800px;margin:50px auto;background:#111;color:#eee}
            a{color:#00d4ff}h1{color:#7b2ff7}code{background:#222;padding:2px 6px;border-radius:3px}
            .vuln{background:#1a1a2e;padding:15px;margin:10px 0;border-radius:8px;border-left:3px solid #ff4444}</style></head>
            <body>
            <h1>🔄 Resurface Test App</h1>
            <p>⚠️ Intentionally vulnerable. For testing only.</p>
            
            <div class="vuln">
                <h3>1. Reflected XSS</h3>
                <a href="/search?q=test">/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</a>
            </div>
            
            <div class="vuln">
                <h3>2. Stored XSS</h3>
                <a href="/comments">/comments</a> (post a comment with JS)
            </div>
            
            <div class="vuln">
                <h3>3. IDOR — User Profile</h3>
                <a href="/api/user?id=1">/api/user?id=1</a> (change id to see other users)
            </div>
            
            <div class="vuln">
                <h3>4. Open Redirect</h3>
                <a href="/redirect?url=https://evil.com">/redirect?url=https://evil.com</a>
            </div>
            
            <div class="vuln">
                <h3>5. Path Traversal</h3>
                <a href="/file?name=readme.txt">/file?name=../../etc/passwd</a>
            </div>
            
            <div class="vuln">
                <h3>6. Information Disclosure</h3>
                <a href="/debug/config">/debug/config</a> (exposes secrets)
            </div>
            
            <div class="vuln">
                <h3>7. CSRF — Password Change</h3>
                <a href="/settings">/settings</a> (no CSRF token)
            </div>
            
            </body></html>
            """)
        
        # === REFLECTED XSS ===
        elif path == "/search":
            query = params.get("q", [""])[0]
            # VULNERABLE: No sanitization — reflects input directly
            self._send(200, f"""
            <html><head><title>Search Results</title></head><body>
            <h2>Search Results for: {query}</h2>
            <p>No results found for "{query}"</p>
            <a href="/">Back to Home</a>
            </body></html>
            """)
        
        # === STORED XSS — View Comments ===
        elif path == "/comments":
            comments_html = ""
            for c in COMMENTS:
                # VULNERABLE: No sanitization on stored comments
                comments_html += f"<div style='background:#1a1a2e;padding:10px;margin:5px 0;border-radius:5px'><b>{c['user']}</b>: {c['text']}</div>"
            
            self._send(200, f"""
            <html><head><title>Comments</title>
            <style>body{{font-family:sans-serif;max-width:600px;margin:50px auto;background:#111;color:#eee}}</style></head>
            <body>
            <h2>Comments</h2>
            {comments_html}
            <h3>Add Comment</h3>
            <form method="POST" action="/comments">
                <input name="user" placeholder="Name" style="padding:8px;width:200px"><br><br>
                <textarea name="text" placeholder="Comment" style="padding:8px;width:400px;height:80px"></textarea><br><br>
                <button type="submit" style="padding:8px 20px;background:#7b2ff7;color:white;border:none;border-radius:5px;cursor:pointer">Post</button>
            </form>
            <br><a href="/">Back to Home</a>
            </body></html>
            """)
        
        # === IDOR — User API ===
        elif path == "/api/user":
            user_id = params.get("id", [""])[0]
            # VULNERABLE: No authorization check — any user can view any profile
            user = USERS.get(user_id)
            if user:
                self._send(200, json.dumps(user, indent=2), "application/json")
            else:
                self._send(404, json.dumps({"error": "User not found"}), "application/json")
        
        # === OPEN REDIRECT ===
        elif path == "/redirect":
            url = params.get("url", [""])[0]
            # VULNERABLE: No validation on redirect target
            if url:
                self.send_response(302)
                self.send_header("Location", url)
                self.end_headers()
            else:
                self._send(400, "Missing url parameter")
        
        # === PATH TRAVERSAL ===
        elif path == "/file":
            filename = params.get("name", [""])[0]
            # VULNERABLE: No path sanitization
            filepath = os.path.join("/root/resurface/testapp/files", filename)
            try:
                with open(filepath) as f:
                    content = f.read()
                self._send(200, f"<pre>{content}</pre>")
            except:
                self._send(404, f"File not found: {filename}")
        
        # === INFORMATION DISCLOSURE ===
        elif path == "/debug/config":
            # VULNERABLE: Exposes sensitive configuration
            self._send(200, json.dumps(CONFIG, indent=2), "application/json")
        
        elif path == "/debug/env":
            # VULNERABLE: Exposes environment variables
            env = {k: v for k, v in os.environ.items()}
            self._send(200, json.dumps(env, indent=2), "application/json")
        
        # === CSRF — Settings Page ===
        elif path == "/settings":
            self._send(200, """
            <html><head><title>Settings</title>
            <style>body{font-family:sans-serif;max-width:500px;margin:50px auto;background:#111;color:#eee}
            input{padding:8px;width:300px;margin:5px 0}</style></head>
            <body>
            <h2>Account Settings</h2>
            <form method="POST" action="/settings/password">
                <label>New Password:</label><br>
                <input type="password" name="new_password"><br><br>
                <label>Confirm Password:</label><br>
                <input type="password" name="confirm_password"><br><br>
                <button type="submit" style="padding:8px 20px;background:#ff4444;color:white;border:none;border-radius:5px">Change Password</button>
            </form>
            <p style="color:#888">⚠️ No CSRF token protection</p>
            <br><a href="/" style="color:#00d4ff">Back to Home</a>
            </body></html>
            """)
        
        # === HEALTH CHECK ===
        elif path == "/health":
            self._send(200, json.dumps({"status": "ok"}), "application/json")
        
        else:
            self._send(404, "<h1>404 Not Found</h1>")
    
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(body)
        
        # === STORED XSS — Post Comment ===
        if path == "/comments":
            user = params.get("user", ["Anonymous"])[0]
            text = params.get("text", [""])[0]
            # VULNERABLE: Stores unsanitized input
            COMMENTS.append({"user": user, "text": text})
            self.send_response(302)
            self.send_header("Location", "/comments")
            self.end_headers()
        
        # === CSRF — Password Change ===
        elif path == "/settings/password":
            new_pw = params.get("new_password", [""])[0]
            # VULNERABLE: No CSRF token, no old password verification
            self._send(200, f"""
            <html><body style="font-family:sans-serif;background:#111;color:#eee;text-align:center;padding:50px">
            <h2>✅ Password changed successfully!</h2>
            <p>New password set to: {html.escape(new_pw)}</p>
            <a href="/" style="color:#00d4ff">Back to Home</a>
            </body></html>
            """)
        
        else:
            self._send(404, "<h1>404 Not Found</h1>")


def main():
    port = 9999
    server = HTTPServer(("127.0.0.1", port), VulnerableHandler)
    print(f"🎯 Resurface Test App running on http://127.0.0.1:{port}")
    print(f"   ⚠️  Bound to localhost only — not exposed to internet")
    print(f"   Vulns: XSS, IDOR, Open Redirect, Path Traversal, Info Disclosure, CSRF")
    print(f"   Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
