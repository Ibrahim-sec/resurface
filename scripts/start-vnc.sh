#!/bin/bash
# ============================================
# Secure noVNC launcher for Resurface
# Binds to localhost ONLY — access via SSH tunnel
# ============================================
#
# USAGE:
# 1. On VPS:   ./scripts/start-vnc.sh
# 2. On laptop: ssh -L 6080:localhost:6080 root@your-vps-ip
# 3. Open:     http://localhost:6080/vnc.html
#

set -e

echo "🖥️  Starting secure noVNC (localhost only)..."

# Kill any existing instances
killall -9 Xvfb x11vnc websockify 2>/dev/null || true
sleep 1

# Start virtual display
Xvfb :99 -screen 0 1280x720x24 &
export DISPLAY=:99
echo "   ✅ Virtual display :99 started"

# Start VNC (localhost only)
x11vnc -display :99 -nopw -forever -shared -localhost &
echo "   ✅ VNC server on localhost:5900"

# Start noVNC (localhost only)
websockify --web /usr/share/novnc --heartbeat=30 127.0.0.1:6080 localhost:5900 &
echo "   ✅ noVNC on localhost:6080"

sleep 1
echo ""
echo "🔒 All services bound to localhost — NOT exposed to internet"
echo ""
echo "📺 To watch from your laptop:"
echo "   1. SSH tunnel: ssh -L 6080:localhost:6080 root@YOUR_VPS_IP"
echo "   2. Open: http://localhost:6080/vnc.html"
echo ""
echo "   Then run Resurface with --browser flag:"
echo "   DISPLAY=:99 python3 resurface.py replay --report 900001 --target http://127.0.0.1:9999 --browser"
