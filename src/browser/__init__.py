"""
Browser module — shared constants and helpers for all browser engines.
"""

# Default Chromium launch args applied to every browser instance.
# Suppresses password manager popups, translate bars, info bars,
# first-run wizards, and other UI noise that confuses the agent.
DEFAULT_CHROME_ARGS = [
    '--no-sandbox',
    '--disable-web-security',
    '--disable-save-password-bubble',
    '--disable-features=PasswordManager,PasswordManagerOnboarding,PasswordManagerBubble,'
    'PasswordLeakDetection,PasswordCheck,PasswordImport,'
    'TranslateUI,InfoBars,AutofillServerCommunication,AutofillCreditCardUpload,'
    'PasswordChangeInSettings,PasswordManagerAccountStorage',
    '--disable-infobars',
    '--disable-component-update',
    '--disable-default-apps',
    '--no-first-run',
    '--password-store=basic',
    '--disable-notifications',
    '--deny-permission-prompts',
    # Extra flags to suppress credential prompts
    '--disable-blink-features=CredentialManagerAccess',
    '--disable-prompt-on-repost',
    '--disable-site-isolation-trials',
]
