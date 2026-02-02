"""
Target Profiler — automatic tech stack detection before replay.
Runs quick HTTP requests to fingerprint the target's framework,
server, and security features. Feeds context to the browser agent.
"""
import json
import re
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from loguru import logger


@dataclass
class TargetProfile:
    """Fingerprinted target information."""
    url: str = ""
    server: str = ""                     # e.g. "Express", "nginx", "Apache"
    framework: str = ""                  # e.g. "Angular", "React", "Django"
    language: str = ""                   # e.g. "Node.js", "Python", "PHP"
    waf: str = ""                        # e.g. "Cloudflare", "ModSecurity"
    auth_type: str = ""                  # e.g. "JWT", "Session cookie", "Basic"
    csrf_protection: bool = False
    cors_open: bool = False
    security_headers: dict = field(default_factory=dict)
    interesting_headers: dict = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    notes: str = ""
    
    def format_for_prompt(self) -> str:
        """Format as text for the agent prompt."""
        parts = [f"## Target Profile: {self.url}"]
        if self.server: parts.append(f"- Server: {self.server}")
        if self.framework: parts.append(f"- Frontend framework: {self.framework}")
        if self.language: parts.append(f"- Backend: {self.language}")
        if self.waf: parts.append(f"- WAF detected: {self.waf} ⚠️ Payloads may need encoding/bypass")
        if self.auth_type: parts.append(f"- Auth type: {self.auth_type}")
        if self.csrf_protection: parts.append(f"- CSRF protection: YES — extract tokens before POST requests")
        if self.cors_open: parts.append(f"- CORS: Open (Access-Control-Allow-Origin: *)")
        if self.technologies: parts.append(f"- Technologies: {', '.join(self.technologies)}")
        if self.security_headers:
            sec = ", ".join(f"{k}" for k in self.security_headers.keys())
            parts.append(f"- Security headers: {sec}")
        if self.notes: parts.append(f"- Notes: {self.notes}")
        return "\n".join(parts)


class TargetProfiler:
    """Profiles a target URL by analyzing HTTP responses."""
    
    # Framework detection patterns (in HTML body)
    FRAMEWORK_PATTERNS = {
        "Angular": [r'ng-app', r'ng-controller', r'angular\.min\.js', r'ng-version', r'\[\(ngModel\)\]'],
        "React": [r'react\.production\.min\.js', r'reactDOM', r'data-reactroot', r'__NEXT_DATA__'],
        "Vue.js": [r'vue\.min\.js', r'v-bind:', r'v-on:', r'Vue\.component'],
        "jQuery": [r'jquery\.min\.js', r'jquery-\d'],
        "Bootstrap": [r'bootstrap\.min\.(css|js)'],
        "Juice Shop": [r'OWASP Juice Shop', r'juice-shop'],
        "WordPress": [r'wp-content', r'wp-includes', r'wp-json'],
        "Django": [r'csrfmiddlewaretoken', r'__admin'],
        "Laravel": [r'laravel_session', r'XSRF-TOKEN'],
        "Express": [],  # Detected via headers
    }
    
    # Server detection from headers
    SERVER_PATTERNS = {
        "Express": ["express"],
        "nginx": ["nginx"],
        "Apache": ["apache"],
        "IIS": ["microsoft-iis"],
        "Gunicorn": ["gunicorn"],
        "Werkzeug": ["werkzeug"],
        "Kestrel": ["kestrel"],
    }
    
    # WAF detection
    WAF_PATTERNS = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "awswaf"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Sucuri": ["x-sucuri"],
        "Akamai": ["akamai"],
    }

    def profile(self, target_url: str) -> TargetProfile:
        """Profile a target by making HTTP requests and analyzing responses."""
        profile = TargetProfile(url=target_url)
        logger.info(f"  🔎 Profiling target: {target_url}")
        
        try:
            req = urllib.request.Request(target_url)
            req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            resp = urllib.request.urlopen(req, timeout=15)
            
            # Read headers
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read().decode("utf-8", errors="replace")[:50000]
            
            # Server detection
            server_header = headers.get("server", "").lower()
            x_powered = headers.get("x-powered-by", "").lower()
            
            for name, patterns in self.SERVER_PATTERNS.items():
                if any(p in server_header for p in patterns) or any(p in x_powered for p in patterns):
                    profile.server = name
                    break
            if not profile.server and server_header:
                profile.server = server_header
            
            # Language detection from headers
            if "x-powered-by" in headers:
                xp = headers["x-powered-by"]
                if "php" in xp.lower(): profile.language = "PHP"
                elif "asp.net" in xp.lower(): profile.language = "ASP.NET"
                elif "express" in xp.lower(): profile.language = "Node.js"
            
            # Framework detection from body
            for framework, patterns in self.FRAMEWORK_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        profile.framework = framework
                        break
                if profile.framework:
                    break
            
            # WAF detection
            all_header_text = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
            for waf_name, indicators in self.WAF_PATTERNS.items():
                if any(ind in all_header_text for ind in indicators):
                    profile.waf = waf_name
                    break
            
            # Auth type detection
            if "authorization" in body.lower() or "jwt" in body.lower():
                profile.auth_type = "JWT"
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                if "session" in set_cookie.lower():
                    profile.auth_type = profile.auth_type or "Session cookie"
                if "phpsessid" in set_cookie.lower():
                    profile.auth_type = "PHP Session"
                    profile.language = profile.language or "PHP"
            
            # CSRF detection
            if re.search(r'csrf|_token|csrfmiddleware', body, re.IGNORECASE):
                profile.csrf_protection = True
            
            # CORS detection
            if headers.get("access-control-allow-origin") == "*":
                profile.cors_open = True
            
            # Security headers
            security_header_names = [
                "content-security-policy", "x-frame-options", "x-content-type-options",
                "x-xss-protection", "strict-transport-security", "referrer-policy",
                "permissions-policy"
            ]
            for h in security_header_names:
                if h in headers:
                    profile.security_headers[h] = headers[h]
            
            # Technology list
            techs = []
            if profile.server: techs.append(profile.server)
            if profile.framework: techs.append(profile.framework)
            if profile.language: techs.append(profile.language)
            if profile.waf: techs.append(f"WAF:{profile.waf}")
            profile.technologies = techs
            
            # Interesting headers
            for k, v in headers.items():
                if k.startswith("x-") and k not in security_header_names:
                    profile.interesting_headers[k] = v
            
            logger.info(f"  🔎 Profile: {', '.join(techs) if techs else 'unknown stack'}")
            
        except urllib.error.HTTPError as e:
            profile.notes = f"HTTP {e.code} on GET {target_url}"
            # Still try to read headers
            headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, 'headers') else {}
            server_header = headers.get("server", "")
            if server_header:
                profile.server = server_header
            logger.info(f"  🔎 Profile: HTTP {e.code} (limited info)")
        except Exception as e:
            profile.notes = f"Profiling failed: {e}"
            logger.warning(f"  🔎 Profile failed: {e}")
        
        return profile
