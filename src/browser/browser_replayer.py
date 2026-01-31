"""
Browser-based PoC replay engine — uses Playwright + Gemini LLM to reproduce 
browser-dependent vulnerabilities (XSS, CSRF, clickjacking, DOM-based bugs)
"""
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
from datetime import datetime
from loguru import logger

from src.models import (
    ParsedReport, ReplayReport, ReplayResult, ReplayEvidence, PoC_Step
)


BROWSER_AGENT_PROMPT = """You are an autonomous browser-based vulnerability tester. You control a real web browser via Playwright.

## Vulnerability Being Tested
- **Title:** {title}
- **Type:** {vuln_type}
- **Description:** {description}
- **Target URL:** {target_url}

## PoC Steps to Reproduce
{steps_text}

## Current Browser State
- **Current URL:** {current_url}
- **Page Title:** {page_title}
- **Visible Text (first 2000 chars):** 
{page_text}

## Your Task
Based on the current browser state and the PoC steps, provide the NEXT browser action to take.

Respond with JSON:
{{
    "action": "<one of: navigate, click, type, execute_js, screenshot, wait, done>",
    "target": "<CSS selector for click/type, URL for navigate, JS code for execute_js>",
    "value": "<text to type, or null>",
    "description": "<what this action does and why>",
    "step_number": <which PoC step this corresponds to>,
    "is_final_step": <true if this is the last action needed>,
    "vulnerability_detected": <true/false/null — set true if you can already see the vuln is present>
}}

## Rules
- Execute ONE action at a time
- For XSS: navigate to the URL with the payload, then check if alert/DOM manipulation occurred
- For CSRF: craft and submit the form
- For IDOR: navigate with modified parameters and check the response
- Use execute_js to check for XSS indicators (alert boxes, DOM changes, cookie access)
- After the final step, set is_final_step to true
- If you detect the vulnerability already, set vulnerability_detected to true
- Return ONLY valid JSON
"""


class BrowserReplayer:
    """Replays browser-based PoCs using Playwright + Gemini LLM"""
    
    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash",
                 headless: bool = True, screenshot: bool = True,
                 timeout: int = 60000, evidence_dir: str = "data/results"):
        self.api_key = api_key
        self.model = model
        self.headless = headless
        self.screenshot = screenshot
        self.timeout = timeout
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def _call_gemini(self, prompt: str, max_retries: int = 5) -> Optional[str]:
        """Call Gemini API with retry"""
        url = self.GEMINI_URL.format(model=self.model) + f"?key={self.api_key}"
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json"
            }
        }
        
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(url, headers={'Content-Type': 'application/json'})
                req.data = json.dumps(payload).encode()
                resp = urllib.request.urlopen(req, timeout=30)
                data = json.loads(resp.read())
                
                candidates = data.get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    if parts:
                        return parts[0].get('text', '')
                return None
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    wait = (2 ** attempt) * 5
                    logger.warning(f"Rate limited. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                logger.error(f"Gemini call failed: HTTP {e.code}")
                return None
            except Exception as e:
                logger.error(f"Gemini call failed: {e}")
                return None
        return None
    
    def _execute_browser_action(self, page, action: dict, report_id: int, 
                                 step_num: int) -> ReplayEvidence:
        """Execute a single browser action from LLM guidance"""
        evidence = ReplayEvidence(step_number=step_num)
        action_type = action.get('action', '')
        target = action.get('target', '')
        value = action.get('value', '')
        description = action.get('description', '')
        
        evidence.notes = f"Action: {action_type} | {description}"
        
        try:
            if action_type == 'navigate':
                logger.info(f"  🌐 Navigating to: {target}")
                page.goto(target, timeout=self.timeout, wait_until='domcontentloaded')
                evidence.request_sent = f"NAVIGATE: {target}"
                evidence.response_received = f"Loaded: {page.url} | Title: {page.title()}"
                evidence.status_code = 200
                
            elif action_type == 'click':
                logger.info(f"  🖱️ Clicking: {target}")
                page.click(target, timeout=10000)
                evidence.request_sent = f"CLICK: {target}"
                evidence.response_received = f"Clicked. Current URL: {page.url}"
                
            elif action_type == 'type':
                logger.info(f"  ⌨️ Typing into: {target}")
                page.fill(target, value, timeout=10000)
                evidence.request_sent = f"TYPE: {target} = {value}"
                evidence.response_received = f"Typed. Current URL: {page.url}"
                
            elif action_type == 'execute_js':
                logger.info(f"  📜 Executing JS: {target[:80]}...")
                result = page.evaluate(target)
                evidence.request_sent = f"JS: {target}"
                evidence.response_received = f"Result: {json.dumps(result) if result else 'undefined'}"
                
            elif action_type == 'wait':
                wait_time = int(value) if value else 2
                logger.info(f"  ⏳ Waiting {wait_time}s...")
                time.sleep(wait_time)
                evidence.notes += f" (waited {wait_time}s)"
                
            elif action_type == 'done':
                logger.info(f"  ✅ LLM signals done")
                evidence.notes = "LLM determined replay is complete"
            
            # Take screenshot after each action
            if self.screenshot and action_type != 'done':
                ss_path = self.evidence_dir / f"{report_id}_step{step_num}.png"
                page.screenshot(path=str(ss_path), full_page=False)
                evidence.screenshot_path = str(ss_path)
                logger.info(f"  📸 Screenshot: {ss_path}")
                
        except Exception as e:
            evidence.notes += f" | ERROR: {e}"
            logger.warning(f"  ⚠️ Action failed: {e}")
        
        return evidence
    
    def replay(self, parsed_report: ParsedReport,
               target_override: str = None,
               max_actions: int = 15) -> ReplayReport:
        """
        Replay a parsed report using LLM-driven browser automation.
        
        The LLM receives the PoC steps + current browser state and decides
        what to do next, one action at a time, until done.
        """
        from playwright.sync_api import sync_playwright
        
        start_time = time.time()
        report_id = parsed_report.report_id
        evidence_list = []
        vulnerability_detected = False
        
        logger.info(f"🌐 Browser replay for report {report_id}: {parsed_report.title[:50]}")
        
        # Build steps text for the prompt
        steps_text = ""
        for step in parsed_report.steps:
            steps_text += f"{step.order}. {step.description}\n"
            if step.url:
                url = step.url
                if target_override and parsed_report.target_domain:
                    url = url.replace(parsed_report.target_domain, target_override.replace('http://', '').replace('https://', '').rstrip('/'))
                steps_text += f"   URL: {url}\n"
            if step.payload:
                steps_text += f"   Payload: {step.payload}\n"
            if step.expected_behavior:
                steps_text += f"   Expected: {step.expected_behavior}\n"
        
        target_url = target_override or parsed_report.target_url or ""
        
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=self.headless,
                args=['--no-sandbox', '--disable-web-security']
            )
            
            context = browser.new_context(
                viewport={'width': 1250, 'height': 680},
                ignore_https_errors=True
            )
            page = context.new_page()
            
            # Capture console messages (important for XSS detection)
            console_messages = []
            page.on('console', lambda msg: console_messages.append(f"[{msg.type}] {msg.text}"))
            
            # Capture dialogs (alert/confirm/prompt — XSS indicator)
            dialogs_seen = []
            def handle_dialog(dialog):
                dialogs_seen.append(f"{dialog.type}: {dialog.message}")
                logger.info(f"  🚨 Dialog detected: {dialog.type} — {dialog.message}")
                dialog.accept()
            page.on('dialog', handle_dialog)
            
            # Navigate to initial target
            if target_url:
                try:
                    page.goto(target_url, timeout=self.timeout, wait_until='domcontentloaded')
                    logger.info(f"  Loaded: {page.url}")
                except:
                    logger.warning(f"  Failed to load initial URL: {target_url}")
            
            # LLM-driven action loop
            for action_num in range(max_actions):
                # Get current page state
                try:
                    current_url = page.url
                    page_title = page.title()
                    page_text = page.inner_text('body')[:2000]
                except:
                    current_url = "about:blank"
                    page_title = ""
                    page_text = ""
                
                # Add dialog/console info to page state
                if dialogs_seen:
                    page_text += f"\n\n[DIALOGS DETECTED: {'; '.join(dialogs_seen)}]"
                if console_messages:
                    page_text += f"\n\n[CONSOLE: {'; '.join(console_messages[-5:])}]"
                
                # Ask LLM what to do next
                prompt = BROWSER_AGENT_PROMPT.format(
                    title=parsed_report.title,
                    vuln_type=parsed_report.vuln_type.value,
                    description=parsed_report.description,
                    target_url=target_url,
                    steps_text=steps_text,
                    current_url=current_url,
                    page_title=page_title,
                    page_text=page_text
                )
                
                response_text = self._call_gemini(prompt)
                if not response_text:
                    logger.error("No LLM response, stopping replay")
                    break
                
                try:
                    text = response_text.strip()
                    if text.startswith('```'):
                        text = text.split('\n', 1)[1]
                        text = text.rsplit('```', 1)[0]
                    action = json.loads(text)
                except json.JSONDecodeError:
                    logger.error(f"Invalid LLM JSON: {response_text[:200]}")
                    break
                
                # Execute the action
                evidence = self._execute_browser_action(page, action, report_id, action_num + 1)
                evidence_list.append(evidence)
                
                # Check if LLM detected vulnerability
                if action.get('vulnerability_detected'):
                    vulnerability_detected = True
                    logger.info(f"  🔴 LLM reports vulnerability detected!")
                
                # Check if done
                if action.get('is_final_step') or action.get('action') == 'done':
                    logger.info(f"  Replay complete after {action_num + 1} actions")
                    break
                
                # Small delay between actions (visible on noVNC)
                time.sleep(1)
            
            # Final screenshot
            try:
                final_ss = self.evidence_dir / f"{report_id}_final.png"
                page.screenshot(path=str(final_ss), full_page=True)
                logger.info(f"  📸 Final screenshot: {final_ss}")
            except:
                pass
            
            # Check for XSS indicators
            if dialogs_seen:
                vulnerability_detected = True
                logger.info(f"  🚨 XSS confirmed: {len(dialogs_seen)} dialog(s) triggered")
            
            browser.close()
        
        duration = time.time() - start_time
        
        # Determine preliminary result
        if vulnerability_detected:
            result = ReplayResult.VULNERABLE
        elif dialogs_seen:
            result = ReplayResult.VULNERABLE
        else:
            result = ReplayResult.INCONCLUSIVE
        
        report = ReplayReport(
            report_id=report_id,
            parsed_report=parsed_report,
            result=result,
            evidence=evidence_list,
            replayed_at=datetime.now(),
            duration_seconds=duration,
            target_url=target_url
        )
        
        logger.info(
            f"Browser replay done for {report_id}: "
            f"{len(evidence_list)} actions, {duration:.1f}s, "
            f"dialogs={len(dialogs_seen)}, result={result.value}"
        )
        
        return report
