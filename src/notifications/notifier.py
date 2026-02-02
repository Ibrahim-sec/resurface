"""
Resurface Notification System

Sends alerts when vulnerabilities are detected during replay.
Supports: Console (Rich), Telegram, Discord, Slack.
Uses only stdlib (urllib.request) for HTTP — no extra dependencies.
"""
import json
import os
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

try:
    from loguru import logger
except ImportError:
    import logging as logger

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class Notifier:
    """
    Multi-channel notification dispatcher.
    
    Config shape (from NotificationConfig dataclass):
        enabled: bool
        on: list[str]           # e.g. ["vulnerable", "partial"]
        channels:
            telegram: {enabled, bot_token, chat_id}
            discord:  {enabled, webhook_url}
            slack:    {enabled, webhook_url}
    """

    def __init__(self, config=None):
        """
        Args:
            config: A NotificationConfig dataclass (or None to disable).
        """
        self.enabled = False
        self.trigger_on = ["vulnerable", "partial"]
        self.telegram = {}
        self.discord = {}
        self.slack = {}

        if config and getattr(config, 'enabled', False):
            self.enabled = True
            self.trigger_on = getattr(config, 'on', ["vulnerable", "partial"]) or ["vulnerable", "partial"]

            # Telegram
            tg = getattr(config, 'telegram', None)
            if tg and getattr(tg, 'enabled', False):
                self.telegram = {
                    'bot_token': getattr(tg, 'bot_token', '') or os.environ.get('RESURFACE_TELEGRAM_TOKEN', ''),
                    'chat_id': getattr(tg, 'chat_id', '') or os.environ.get('RESURFACE_TELEGRAM_CHAT_ID', ''),
                }

            # Discord
            dc = getattr(config, 'discord', None)
            if dc and getattr(dc, 'enabled', False):
                self.discord = {
                    'webhook_url': getattr(dc, 'webhook_url', '') or os.environ.get('RESURFACE_DISCORD_WEBHOOK', ''),
                }

            # Slack
            sl = getattr(config, 'slack', None)
            if sl and getattr(sl, 'enabled', False):
                self.slack = {
                    'webhook_url': getattr(sl, 'webhook_url', '') or os.environ.get('RESURFACE_SLACK_WEBHOOK', ''),
                }

    def should_notify(self, result_str: str) -> bool:
        """Check if this result status should trigger a notification."""
        if not self.enabled:
            return False
        return result_str.lower() in [t.lower() for t in self.trigger_on]

    def notify(self, report_id, title: str, vuln_type: str, severity: str,
               confidence: float, target_url: str, result: str,
               analysis: str = ""):
        """
        Send notification across all enabled channels.

        Args:
            report_id: Report ID
            title: Report title
            vuln_type: Vulnerability type (e.g. 'xss_reflected')
            severity: Severity rating (e.g. 'high')
            confidence: Confidence score 0.0-1.0
            target_url: URL that was tested
            result: Result string ('vulnerable', 'partial', etc.)
            analysis: Brief LLM analysis text
        """
        result_lower = result.lower() if isinstance(result, str) else str(result).lower()
        
        if not self.should_notify(result_lower):
            return

        payload = {
            'report_id': report_id,
            'title': title,
            'vuln_type': vuln_type,
            'severity': severity,
            'confidence': confidence,
            'target_url': target_url,
            'result': result_lower,
            'analysis': (analysis[:300] + '...' if len(analysis) > 300 else analysis) if analysis else '',
            'timestamp': datetime.now().isoformat(),
        }

        # Console always fires
        self._notify_console(payload)

        # External channels
        if self.telegram.get('bot_token') and self.telegram.get('chat_id'):
            try:
                self._notify_telegram(payload)
            except Exception as e:
                logger.warning(f"Telegram notification failed: {e}")

        if self.discord.get('webhook_url'):
            try:
                self._notify_discord(payload)
            except Exception as e:
                logger.warning(f"Discord notification failed: {e}")

        if self.slack.get('webhook_url'):
            try:
                self._notify_slack(payload)
            except Exception as e:
                logger.warning(f"Slack notification failed: {e}")

    # ──────────────────────────────────────
    #  Console (Rich)
    # ──────────────────────────────────────

    def _notify_console(self, payload: dict):
        """Rich-formatted terminal alert."""
        result = payload['result']
        emoji = '🔴' if result == 'vulnerable' else '🟡'
        tag = 'VULNERABLE' if result == 'vulnerable' else 'PARTIAL FIX'

        if RICH_AVAILABLE:
            console = Console()
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column(style="bold cyan", width=14)
            table.add_column()
            table.add_row("Report", f"#{payload['report_id']}")
            table.add_row("Title", payload['title'])
            table.add_row("Type", payload['vuln_type'])
            table.add_row("Severity", payload['severity'].upper())
            table.add_row("Confidence", f"{payload['confidence']:.0%}")
            table.add_row("Target", payload['target_url'])
            if payload.get('analysis'):
                table.add_row("Analysis", payload['analysis'][:200])

            panel = Panel(
                table,
                title=f"{emoji} {tag} — Bug Resurfaced!",
                border_style="red" if result == 'vulnerable' else "yellow",
                expand=False,
            )
            console.print()
            console.print(panel)
            console.print()
        else:
            # Fallback plain text
            print(f"\n{'='*60}")
            print(f"  {emoji} {tag} — Bug Resurfaced!")
            print(f"{'='*60}")
            print(f"  Report:     #{payload['report_id']}")
            print(f"  Title:      {payload['title']}")
            print(f"  Type:       {payload['vuln_type']}")
            print(f"  Severity:   {payload['severity']}")
            print(f"  Confidence: {payload['confidence']:.0%}")
            print(f"  Target:     {payload['target_url']}")
            if payload.get('analysis'):
                print(f"  Analysis:   {payload['analysis'][:200]}")
            print(f"{'='*60}\n")

    # ──────────────────────────────────────
    #  Telegram
    # ──────────────────────────────────────

    def _notify_telegram(self, payload: dict):
        """Send Telegram message via Bot API."""
        token = self.telegram['bot_token']
        chat_id = self.telegram['chat_id']
        
        result = payload['result']
        emoji = '🔴' if result == 'vulnerable' else '🟡'
        tag = 'VULNERABLE' if result == 'vulnerable' else 'PARTIAL FIX'

        text = (
            f"{emoji} *Resurface Alert — {tag}*\n\n"
            f"*Report:* #{payload['report_id']}\n"
            f"*Title:* {_tg_escape(payload['title'])}\n"
            f"*Type:* {payload['vuln_type']}\n"
            f"*Severity:* {payload['severity'].upper()}\n"
            f"*Confidence:* {payload['confidence']:.0%}\n"
            f"*Target:* `{payload['target_url']}`\n"
        )
        if payload.get('analysis'):
            text += f"\n_{_tg_escape(payload['analysis'][:200])}_"

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        body = json.dumps({
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'Markdown',
            'disable_web_page_preview': True,
        }).encode('utf-8')

        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=10)
        logger.info(f"Telegram notification sent for report #{payload['report_id']}")

    # ──────────────────────────────────────
    #  Discord
    # ──────────────────────────────────────

    def _notify_discord(self, payload: dict):
        """Send Discord webhook embed."""
        webhook_url = self.discord['webhook_url']

        result = payload['result']
        color = 0xFF0000 if result == 'vulnerable' else 0xFFAA00
        tag = 'VULNERABLE' if result == 'vulnerable' else 'PARTIAL FIX'

        embed = {
            'title': f"🔄 Resurface Alert — {tag}",
            'color': color,
            'fields': [
                {'name': 'Report', 'value': f"#{payload['report_id']}", 'inline': True},
                {'name': 'Severity', 'value': payload['severity'].upper(), 'inline': True},
                {'name': 'Confidence', 'value': f"{payload['confidence']:.0%}", 'inline': True},
                {'name': 'Title', 'value': payload['title'], 'inline': False},
                {'name': 'Type', 'value': payload['vuln_type'], 'inline': True},
                {'name': 'Target', 'value': f"`{payload['target_url']}`", 'inline': False},
            ],
            'timestamp': payload['timestamp'],
            'footer': {'text': 'Resurface — Bugs don\'t die. They resurface.'},
        }
        if payload.get('analysis'):
            embed['fields'].append({
                'name': 'Analysis',
                'value': payload['analysis'][:1024],
                'inline': False,
            })

        body = json.dumps({'embeds': [embed]}).encode('utf-8')
        req = urllib.request.Request(
            webhook_url, data=body,
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=10)
        logger.info(f"Discord notification sent for report #{payload['report_id']}")

    # ──────────────────────────────────────
    #  Slack
    # ──────────────────────────────────────

    def _notify_slack(self, payload: dict):
        """Send Slack webhook block message."""
        webhook_url = self.slack['webhook_url']

        result = payload['result']
        emoji = ':red_circle:' if result == 'vulnerable' else ':large_yellow_circle:'
        tag = 'VULNERABLE' if result == 'vulnerable' else 'PARTIAL FIX'

        blocks = [
            {
                'type': 'header',
                'text': {
                    'type': 'plain_text',
                    'text': f"🔄 Resurface Alert — {tag}",
                    'emoji': True,
                },
            },
            {
                'type': 'section',
                'fields': [
                    {'type': 'mrkdwn', 'text': f"*Report:*\n#{payload['report_id']}"},
                    {'type': 'mrkdwn', 'text': f"*Severity:*\n{payload['severity'].upper()}"},
                    {'type': 'mrkdwn', 'text': f"*Type:*\n{payload['vuln_type']}"},
                    {'type': 'mrkdwn', 'text': f"*Confidence:*\n{payload['confidence']:.0%}"},
                ],
            },
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f"*{payload['title']}*\nTarget: `{payload['target_url']}`",
                },
            },
        ]
        if payload.get('analysis'):
            blocks.append({
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f"_{payload['analysis'][:500]}_",
                },
            })
        blocks.append({'type': 'divider'})

        body = json.dumps({'blocks': blocks}).encode('utf-8')
        req = urllib.request.Request(
            webhook_url, data=body,
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=10)
        logger.info(f"Slack notification sent for report #{payload['report_id']}")


def _tg_escape(text: str) -> str:
    """Escape special Markdown characters for Telegram."""
    for ch in ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']:
        text = text.replace(ch, f'\\{ch}')
    return text
