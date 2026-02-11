"""
Display Manager — Manages Xvfb, x11vnc, and websockify lifecycle.

Starts the display stack before headed browser sessions, stops after.
Cleans up Chrome profile locks to prevent stale lock issues.
"""
import os
import signal
import subprocess
import time
import glob
from pathlib import Path
from loguru import logger


class DisplayManager:
    """Manages virtual display (Xvfb), VNC (x11vnc), and websockify for headed browser mode."""

    def __init__(self, display: str = ":99", vnc_port: int = 5900, ws_port: int = 6081,
                 resolution: str = "1280x1024x24", chrome_profile: str = None):
        self.display = display
        self.vnc_port = vnc_port
        self.ws_port = ws_port
        self.resolution = resolution
        self.chrome_profile = chrome_profile or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'chrome_profile'
        )
        self._pids: dict[str, int] = {}
        self._was_running: dict[str, bool] = {}

    def _is_process_running(self, name: str) -> bool:
        """Check if a process matching name is already running."""
        try:
            result = subprocess.run(
                ['pgrep', '-f', name], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _kill_stale(self, name: str):
        """Kill stale processes matching name."""
        try:
            subprocess.run(['pkill', '-9', '-f', name], capture_output=True, timeout=5)
        except Exception:
            pass

    def _clean_chrome_locks(self):
        """Remove Chrome singleton lock files that prevent launch."""
        lock_files = ['SingletonLock', 'SingletonCookie', 'SingletonSocket']
        for lock in lock_files:
            lock_path = os.path.join(self.chrome_profile, lock)
            if os.path.exists(lock_path):
                try:
                    os.remove(lock_path)
                    logger.debug(f"  🧹 Removed stale lock: {lock}")
                except OSError:
                    pass

        # Also clean temp browser-use dirs
        for d in glob.glob('/tmp/browser-use-user-data-dir-*'):
            try:
                import shutil
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass

    def _start_xvfb(self) -> bool:
        """Start Xvfb virtual display."""
        if self._is_process_running(f'Xvfb {self.display}'):
            logger.info(f"  🖥️  Xvfb {self.display} already running")
            self._was_running['xvfb'] = True
            return True

        try:
            proc = subprocess.Popen(
                ['Xvfb', self.display, '-screen', '0', self.resolution],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            self._pids['xvfb'] = proc.pid
            time.sleep(1)

            if proc.poll() is not None:
                logger.error("  ❌ Xvfb failed to start")
                return False

            logger.info(f"  🖥️  Xvfb started on {self.display} (PID {proc.pid})")
            return True
        except FileNotFoundError:
            logger.error("  ❌ Xvfb not installed")
            return False
        except Exception as e:
            logger.error(f"  ❌ Xvfb error: {e}")
            return False

    def _start_x11vnc(self) -> bool:
        """Start x11vnc VNC server."""
        if self._is_process_running(f'x11vnc.*{self.vnc_port}'):
            logger.info(f"  📺 x11vnc already running on port {self.vnc_port}")
            self._was_running['x11vnc'] = True
            return True

        try:
            proc = subprocess.Popen(
                ['x11vnc', '-display', self.display, '-forever', '-nopw', '-shared',
                 '-rfbport', str(self.vnc_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            self._pids['x11vnc'] = proc.pid
            time.sleep(1)

            if proc.poll() is not None:
                logger.error("  ❌ x11vnc failed to start")
                return False

            logger.info(f"  📺 x11vnc started on port {self.vnc_port} (PID {proc.pid})")
            return True
        except FileNotFoundError:
            logger.warning("  ⚠️  x11vnc not installed — VNC viewing disabled")
            return True  # Not critical
        except Exception as e:
            logger.error(f"  ❌ x11vnc error: {e}")
            return False

    def _start_websockify(self) -> bool:
        """Start websockify for noVNC web access."""
        if self._is_process_running(f'websockify.*{self.ws_port}'):
            logger.info(f"  🌐 websockify already running on port {self.ws_port}")
            self._was_running['websockify'] = True
            return True

        try:
            proc = subprocess.Popen(
                ['websockify', '--web', '/usr/share/novnc', str(self.ws_port),
                 f'localhost:{self.vnc_port}'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            self._pids['websockify'] = proc.pid
            time.sleep(1)

            if proc.poll() is not None:
                logger.error("  ❌ websockify failed to start")
                return False

            logger.info(f"  🌐 websockify started on port {self.ws_port} (PID {proc.pid})")
            return True
        except FileNotFoundError:
            logger.warning("  ⚠️  websockify not installed — noVNC web access disabled")
            return True  # Not critical
        except Exception as e:
            logger.error(f"  ❌ websockify error: {e}")
            return False

    def start(self) -> bool:
        """Start the full display stack. Returns True if display is ready."""
        logger.info("🖥️  Starting display stack...")
        self._was_running = {}

        # Clean chrome locks first
        self._clean_chrome_locks()

        # Set DISPLAY env var
        os.environ['DISPLAY'] = self.display

        # Start in order: Xvfb → x11vnc → websockify
        if not self._start_xvfb():
            return False

        self._start_x11vnc()     # Non-critical
        self._start_websockify()  # Non-critical

        logger.info(f"  ✅ Display stack ready — VNC: http://{{host}}:{self.ws_port}/vnc.html")
        return True

    def stop(self):
        """Stop display stack processes that we started (not pre-existing ones)."""
        logger.info("🖥️  Stopping display stack...")

        # Clean chrome locks
        self._clean_chrome_locks()

        # Kill only processes we started (not pre-existing ones)
        for name, pid in self._pids.items():
            if name in self._was_running:
                logger.debug(f"  Skipping {name} (was already running)")
                continue
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                logger.info(f"  🛑 Stopped {name} (PID {pid})")
            except ProcessLookupError:
                pass  # Already dead
            except Exception as e:
                # Fallback: kill just the process
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

        self._pids.clear()
        logger.info("  ✅ Display stack stopped")

    def __enter__(self):
        """Context manager: start display stack."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager: stop display stack."""
        self.stop()
        return False
