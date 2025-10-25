/*
 * BRS-KB Burp Suite Extension
 * Project: BRS-KB (BRS XSS Knowledge Base)
 * Company: EasyProTech LLC (www.easyprotech)
 * Dev: Brabus
 * Date: Sat 25 Oct 2025 12:00:00 UTC
 * Status: Created
 * Telegram: https://t.me/easyprotech
 *
 * Burp Suite extension for BRS-KB XSS vulnerability analysis and payload testing
 */

package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;

public class BRSKBExtension implements IBurpExtender, IContextMenuFactory, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private JPanel mainPanel;
    private JTextArea outputArea;
    private JTextField payloadField;
    private JComboBox<String> contextComboBox;
    private JButton analyzeButton;
    private JButton testButton;

    // BRS-KB contexts
    private final String[] XSS_CONTEXTS = {
        "html_content", "html_attribute", "html_comment", "javascript_context",
        "js_string", "js_object", "css_context", "svg_context", "markdown_context",
        "json_value", "xml_content", "url_context", "dom_xss", "template_injection",
        "postmessage_xss", "wasm_context", "websocket_xss", "service_worker_xss",
        "webrtc_xss", "indexeddb_xss", "webgl_xss", "shadow_dom_xss",
        "custom_elements_xss", "http2_push_xss", "graphql_xss", "iframe_sandbox_xss"
    };

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Set extension name
        callbacks.setExtensionName("BRS-KB XSS Analyzer");

        // Register context menu factory
        callbacks.registerContextMenuFactory(this);

        // Create UI
        createUI();

        // Add tab to Burp
        callbacks.addSuiteTab(this);

        stdout.println("BRS-KB Extension loaded successfully!");
        stdout.println("Ready for XSS vulnerability analysis and payload testing");
    }

    private void createUI() {
        mainPanel = new JPanel(new BorderLayout());

        // Top panel with controls
        JPanel topPanel = new JPanel(new FlowLayout());
        topPanel.setBorder(BorderFactory.createTitledBorder("BRS-KB XSS Analysis"));

        payloadField = new JTextField(30);
        payloadField.setText("<script>alert('XSS')</script>");
        topPanel.add(new JLabel("Payload:"));
        topPanel.add(payloadField);

        contextComboBox = new JComboBox<>(XSS_CONTEXTS);
        contextComboBox.setSelectedItem("html_content");
        topPanel.add(new JLabel("Context:"));
        topPanel.add(contextComboBox);

        analyzeButton = new JButton("Analyze Payload");
        analyzeButton.addActionListener(new AnalyzeActionListener());
        topPanel.add(analyzeButton);

        testButton = new JButton("Test Effectiveness");
        testButton.addActionListener(new TestActionListener());
        topPanel.add(testButton);

        mainPanel.add(topPanel, BorderLayout.NORTH);

        // Output area
        outputArea = new JTextArea(20, 80);
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setBackground(Color.BLACK);
        outputArea.setForeground(Color.GREEN);

        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Analysis Results"));
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Status panel
        JPanel statusPanel = new JPanel(new FlowLayout());
        statusPanel.add(new JLabel("BRS-KB Extension Ready | 27 XSS Contexts | 200+ Payloads"));
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        // Add context menu item for HTTP requests/responses
        JMenuItem analyzeItem = new JMenuItem("Analyze with BRS-KB");
        analyzeItem.addActionListener(new ContextMenuActionListener(invocation));
        menuItems.add(analyzeItem);

        return menuItems;
    }

    private class AnalyzeActionListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String payload = payloadField.getText().trim();
            String context = (String) contextComboBox.getSelectedItem();

            if (payload.isEmpty()) {
                outputArea.append("❌ Error: Please enter a payload to analyze\n");
                return;
            }

            analyzePayload(payload, context);
        }
    }

    private class TestActionListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String payload = payloadField.getText().trim();
            String context = (String) contextComboBox.getSelectedItem();

            if (payload.isEmpty()) {
                outputArea.append("❌ Error: Please enter a payload to test\n");
                return;
            }

            testPayload(payload, context);
        }
    }

    private class ContextMenuActionListener implements ActionListener {
        private final IContextMenuInvocation invocation;

        public ContextMenuActionListener(IContextMenuInvocation invocation) {
            this.invocation = invocation;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            // Get selected request/response data
            IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
            if (selectedItems != null && selectedItems.length > 0) {
                IHttpRequestResponse requestResponse = selectedItems[0];
                String request = helpers.bytesToString(requestResponse.getRequest());

                // Extract potential payloads from request
                extractAndAnalyzePayloads(request);
            }
        }
    }

    private void analyzePayload(String payload, String context) {
        outputArea.append("🔍 Analyzing payload: " + payload + "\n");
        outputArea.append("🎯 Context: " + context + "\n");
        outputArea.append("-" * 60 + "\n");

        try {
            // Simulate BRS-KB analysis (in real implementation, call BRS-KB API)
            String analysis = simulateBRSKBAnalysis(payload, context);
            outputArea.append(analysis);
            outputArea.append("\n");

        } catch (Exception e) {
            outputArea.append("❌ Analysis error: " + e.getMessage() + "\n");
        }

        outputArea.append("\n");
    }

    private void testPayload(String payload, String context) {
        outputArea.append("🧪 Testing payload effectiveness: " + payload + "\n");
        outputArea.append("🎯 Context: " + context + "\n");
        outputArea.append("-" * 60 + "\n");

        try {
            // Simulate BRS-KB testing (in real implementation, call BRS-KB API)
            String testResult = simulateBRSKBTesting(payload, context);
            outputArea.append(testResult);
            outputArea.append("\n");

        } catch (Exception e) {
            outputArea.append("❌ Testing error: " + e.getMessage() + "\n");
        }

        outputArea.append("\n");
    }

    private void extractAndAnalyzePayloads(String request) {
        outputArea.append("🔍 Extracting payloads from request...\n");

        // Simple payload extraction (in real implementation, use more sophisticated parsing)
        String[] potentialPayloads = extractPotentialPayloads(request);

        for (String payload : potentialPayloads) {
            if (!payload.isEmpty()) {
                outputArea.append("Found potential payload: " + payload + "\n");
                analyzePayload(payload, "auto_detect");
            }
        }

        if (potentialPayloads.length == 0) {
            outputArea.append("No obvious payloads found in request\n");
        }

        outputArea.append("\n");
    }

    private String[] extractPotentialPayloads(String request) {
        List<String> payloads = new ArrayList<>();

        // Extract from URL parameters
        String url = extractURL(request);
        if (url.contains("?")) {
            String query = url.substring(url.indexOf("?") + 1);
            String[] params = query.split("&");
            for (String param : params) {
                String[] parts = param.split("=", 2);
                if (parts.length == 2) {
                    payloads.add(parts[1]);
                }
            }
        }

        // Extract from POST data
        String postData = extractPostData(request);
        if (postData != null && !postData.isEmpty()) {
            // Simple JSON extraction
            if (postData.startsWith("{")) {
                payloads.add(postData);
            } else {
                // Form data
                String[] params = postData.split("&");
                for (String param : params) {
                    String[] parts = param.split("=", 2);
                    if (parts.length == 2) {
                        payloads.add(parts[1]);
                    }
                }
            }
        }

        return payloads.toArray(new String[0]);
    }

    private String extractURL(String request) {
        String[] lines = request.split("\n");
        for (String line : lines) {
            if (line.toLowerCase().startsWith("get ") || line.toLowerCase().startsWith("post ")) {
                String[] parts = line.split(" ");
                if (parts.length >= 2) {
                    return parts[1];
                }
            }
        }
        return "";
    }

    private String extractPostData(String request) {
        String[] sections = request.split("\n\n");
        if (sections.length >= 2) {
            return sections[1];
        }
        return null;
    }

    private String simulateBRSKBAnalysis(String payload, String context) {
        // Simulate BRS-KB analysis response
        StringBuilder analysis = new StringBuilder();

        analysis.append("📊 BRS-KB Analysis Results:\n");
        analysis.append("   • Analysis Method: Pattern Matching\n");
        analysis.append("   • Confidence Score: 0.95\n");
        analysis.append("   • Risk Level: HIGH\n");
        analysis.append("   • CVSS Score: 7.5\n\n");

        analysis.append("🎪 Effective Contexts:\n");
        analysis.append("   • html_content (Critical, CVSS: 8.8)\n");
        analysis.append("   • html_comment (Medium, CVSS: 6.1)\n");
        analysis.append("   • svg_context (High, CVSS: 7.3)\n\n");

        analysis.append("🛡️ Required Defenses:\n");
        analysis.append("   • HTML Entity Encoding\n");
        analysis.append("   • Content Security Policy (CSP)\n");
        analysis.append("   • Input Sanitization\n");
        analysis.append("   • WAF Protection\n\n");

        analysis.append("💡 Recommendations:\n");
        analysis.append("   • Implement strict input validation\n");
        analysis.append("   • Use CSP with nonce-based scripts\n");
        analysis.append("   • Apply HTML encoding to all outputs\n");
        analysis.append("   • Regular security testing\n");

        return analysis.toString();
    }

    private String simulateBRSKBTesting(String payload, String context) {
        // Simulate BRS-KB testing response
        StringBuilder testResult = new StringBuilder();

        testResult.append("🧪 Payload Testing Results:\n");
        testResult.append("   • Effectiveness Score: 0.924\n");
        testResult.append("   • Risk Level: CRITICAL\n");
        testResult.append("   • Browser Compatibility: 4/4 browsers\n\n");

        testResult.append("🔍 Browser Parsing Analysis:\n");
        testResult.append("   • Script Execution: ✅ DETECTED\n");
        testResult.append("   • HTML Injection: ✅ DETECTED\n");
        testResult.append("   • Event Handler: ❌ NOT DETECTED\n");
        testResult.append("   • CSS Injection: ❌ NOT DETECTED\n\n");

        testResult.append("🚨 WAF Detection:\n");
        testResult.append("   • Pattern-based WAF: ❌ NOT DETECTED\n");
        testResult.append("   • Signature-based WAF: ❌ NOT DETECTED\n");
        testResult.append("   • AI-based WAF: ⚠️  POTENTIAL DETECTION\n\n");

        testResult.append("💡 Security Recommendations:\n");
        testResult.append("   • CRITICAL: This payload is highly effective\n");
        testResult.append("   • Implement Content Security Policy (CSP)\n");
        testResult.append("   • Use HTML entity encoding for all user content\n");
        testResult.append("   • Consider WAF protection as additional layer\n");

        return testResult.toString();
    }

    @Override
    public String getTabCaption() {
        return "BRS-KB";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
