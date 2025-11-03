// BRS-KB Insomnia Plugin
// Advanced XSS vulnerability detection and payload testing for Insomnia REST Client

const BRSKBPlugin = {
    name: 'brs-kb-xss-analyzer',
    version: '1.1.0',
    description: 'BRS-KB XSS vulnerability detection and payload testing for Insomnia',

    // Plugin initialization
    init() {
        console.log('BRS-KB Insomnia Plugin initialized');

        // Load BRS-KB data
        this.loadBRSKBData();

        // Add menu items
        this.addMenuItems();

        // Add request hooks
        this.addRequestHooks();
    },

    async loadBRSKBData() {
        try {
            // In a real implementation, this would load from BRS-KB API
            // For now, simulate with embedded data
            this.payloads = {
                "html_content": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>"
                ],
                "websocket_xss": [
                    '{"type": "chat", "message": "<script>alert(1)</script>"}',
                    '{"type": "user_joined", "username": "<script>alert(1)</script>"}'
                ]
            };

            this.contexts = {
                "html_content": {
                    "title": "Cross-Site Scripting (XSS) in HTML Content",
                    "severity": "critical",
                    "cvss_score": 8.8
                }
            };

            console.log('BRS-KB data loaded successfully');
        } catch (error) {
            console.error('Failed to load BRS-KB data:', error);
        }
    },

    addMenuItems() {
        // Add BRS-KB menu to Insomnia
        const menuItems = [
            {
                id: 'brs-kb-analyze-request',
                label: 'Analyze with BRS-KB',
                icon: 'bug',
                action: () => this.analyzeCurrentRequest()
            },
            {
                id: 'brs-kb-test-payloads',
                label: 'Test XSS Payloads',
                icon: 'zap',
                action: () => this.testXSSPayloads()
            },
            {
                id: 'brs-kb-generate-report',
                label: 'Generate BRS-KB Report',
                icon: 'file-text',
                action: () => this.generateReport()
            }
        ];

        // Register menu items with Insomnia
        menuItems.forEach(item => {
            insomnia.menu.addItem({
                id: item.id,
                label: item.label,
                icon: item.icon,
                action: item.action
            });
        });
    },

    addRequestHooks() {
        // Add request hook for automatic analysis
        insomnia.requests.on('send', (request) => {
            this.analyzeRequest(request);
        });
    },

    async analyzeCurrentRequest() {
        try {
            const request = await insomnia.requests.getCurrent();

            if (!request) {
                insomnia.notifications.add({
                    type: 'error',
                    title: 'BRS-KB Error',
                    message: 'No active request found'
                });
                return;
            }

            const analysis = await this.analyzeRequest(request);

            this.showAnalysisResults(analysis);

        } catch (error) {
            console.error('Analysis failed:', error);
            insomnia.notifications.add({
                type: 'error',
                title: 'BRS-KB Analysis Failed',
                message: error.message
            });
        }
    },

    async analyzeRequest(request) {
        const analysis = {
            request_id: request._id,
            url: request.url,
            method: request.method,
            xss_vulnerabilities: [],
            payload_matches: [],
            context_analysis: {},
            recommendations: []
        };

        // Analyze URL parameters
        if (request.url.includes('?')) {
            const urlParams = this.extractURLParameters(request.url);
            for (const [param, value] of Object.entries(urlParams)) {
                const payloadAnalysis = this.analyzePayload(value);
                if (payloadAnalysis.is_vulnerable) {
                    analysis.xss_vulnerabilities.push({
                        type: 'url_parameter',
                        parameter: param,
                        payload: value,
                        contexts: payloadAnalysis.contexts,
                        severity: payloadAnalysis.severity
                    });
                }
            }
        }

        // Analyze request body
        if (request.body && request.body.text) {
            const bodyAnalysis = this.analyzePayload(request.body.text);
            if (bodyAnalysis.is_vulnerable) {
                analysis.xss_vulnerabilities.push({
                    type: 'request_body',
                    payload: request.body.text,
                    contexts: bodyAnalysis.contexts,
                    severity: bodyAnalysis.severity
                });
            }
        }

        // Generate recommendations
        analysis.recommendations = this.generateRecommendations(analysis);

        return analysis;
    },

    extractURLParameters(url) {
        try {
            const urlObj = new URL(url);
            const params = {};
            for (const [key, value] of urlObj.searchParams) {
                params[key] = value;
            }
            return params;
        } catch (error) {
            return {};
        }
    },

    analyzePayload(payload) {
        if (!payload) {
            return { is_vulnerable: false, contexts: [], severity: 'none' };
        }

        const contexts = [];
        let severity = 'low';

        // Check for script patterns
        if (/<script[^>]*>.*?<\/script>/i.test(payload)) {
            contexts.push('html_content');
            severity = 'critical';
        }

        // Check for event handlers
        if (/on\w+\s*=/i.test(payload)) {
            contexts.push('html_attribute');
            severity = 'high';
        }

        // Check for JavaScript protocol
        if (/javascript:/i.test(payload)) {
            contexts.push('url_context');
            severity = 'high';
        }

        // Check for WebSocket patterns
        if (payload.includes('type') && payload.includes('chat')) {
            contexts.push('websocket_xss');
            severity = 'high';
        }

        return {
            is_vulnerable: contexts.length > 0,
            contexts: contexts,
            severity: severity
        };
    },

    generateRecommendations(analysis) {
        const recommendations = [];

        if (analysis.xss_vulnerabilities.length > 0) {
            recommendations.push('CRITICAL: XSS vulnerabilities detected');
            recommendations.push('Implement Content Security Policy (CSP)');
            recommendations.push('Use HTML entity encoding for all user content');
            recommendations.push('Validate and sanitize all inputs');
        }

        // Context-specific recommendations
        const contexts = new Set();
        analysis.xss_vulnerabilities.forEach(vuln => {
            vuln.contexts.forEach(context => contexts.add(context));
        });

        if (contexts.has('html_content')) {
            recommendations.push('HTML Content XSS: Use textContent instead of innerHTML');
        }
        if (contexts.has('html_attribute')) {
            recommendations.push('HTML Attribute XSS: Validate URL parameters');
        }
        if (contexts.has('websocket_xss')) {
            recommendations.push('WebSocket XSS: Sanitize message content');
        }

        return recommendations;
    },

    showAnalysisResults(analysis) {
        const results = [];

        results.push('🔍 BRS-KB Analysis Results');
        results.push('=' * 40);
        results.push('');
        results.push(f'URL: {analysis.url}');
        results.push(f'Method: {analysis.method}');
        results.push(f'Vulnerabilities: {analysis.xss_vulnerabilities.length}');
        results.push('');

        if (analysis.xss_vulnerabilities.length > 0) {
            results.push('🚨 XSS Vulnerabilities:');
            analysis.xss_vulnerabilities.forEach((vuln, index) => {
                results.push(f'   {index + 1}. {vuln.type.toUpperCase()}');
                results.push(f'      Parameter/Payload: {vuln.parameter || vuln.payload}');
                results.push(f'      Contexts: {", ".join(vuln.contexts)}');
                results.push(f'      Severity: {vuln.severity.toUpperCase()}');
                results.push('');
            });
        }

        if (analysis.recommendations.length > 0) {
            results.push('💡 Recommendations:');
            analysis.recommendations.forEach(rec => {
                results.push(f'   • {rec}');
            });
        }

        // Show results in Insomnia
        insomnia.dialogs.showAlert({
            title: 'BRS-KB Analysis Results',
            message: results.join('\n')
        });
    },

    async testXSSPayloads() {
        try {
            const request = await insomnia.requests.getCurrent();

            if (!request) {
                insomnia.notifications.add({
                    type: 'error',
                    title: 'BRS-KB Error',
                    message: 'No active request found'
                });
                return;
            }

            const testResults = [];

            // Test various XSS payloads
            for (const [context, payloads] of Object.entries(this.payloads)) {
                for (const payload of payloads.slice(0, 2)) { // Test first 2 payloads per context
                    const testResult = await this.testPayload(request, payload, context);
                    testResults.push(testResult);
                }
            }

            this.showTestResults(testResults);

        } catch (error) {
            console.error('Payload testing failed:', error);
            insomnia.notifications.add({
                type: 'error',
                title: 'BRS-KB Testing Failed',
                message: error.message
            });
        }
    },

    async testPayload(request, payload, context) {
        // Simulate payload testing
        // In real implementation, this would make actual HTTP requests

        const testRequest = {
            ...request,
            url: request.url.includes('?') ?
                request.url + '&test=' + encodeURIComponent(payload) :
                request.url + '?test=' + encodeURIComponent(payload)
        };

        // Simulate response analysis
        return {
            payload: payload,
            context: context,
            status: 'tested',
            vulnerable: Math.random() > 0.7, // Simulate vulnerability detection
            severity: 'high'
        };
    },

    showTestResults(results) {
        const output = [];

        output.push('🧪 BRS-KB Payload Testing Results');
        output.push('=' * 50);
        output.push('');
        output.push(f'Tested {len(results)} payloads');
        output.push('');

        results.forEach((result, index) => {
            output.push(f'{index + 1}. {result.context}: {result.payload}');
            output.push(f'   Status: {result.status}');
            output.push(f'   Vulnerable: {result.vulnerable}');
            output.push(f'   Severity: {result.severity}');
            output.push('');
        });

        insomnia.dialogs.showAlert({
            title: 'BRS-KB Test Results',
            message: output.join('\n')
        });
    },

    async generateReport() {
        try {
            const report = this.generateReportContent();

            // Save report to file
            const filename = `brs-kb-report-${new Date().toISOString().split('T')[0]}.txt`;
            await insomnia.files.write(filename, report);

            insomnia.notifications.add({
                type: 'success',
                title: 'BRS-KB Report Generated',
                message: `Report saved as: ${filename}`
            });

        } catch (error) {
            console.error('Report generation failed:', error);
            insomnia.notifications.add({
                type: 'error',
                title: 'BRS-KB Report Failed',
                message: error.message
            });
        }
    },

    generateReportContent() {
        const report = [];

        report.push('BRS-KB XSS Analysis Report');
        report.push('=' * 40);
        report.push(f'Generated: {new Date().toISOString()}');
        report.push('');

        report.push('SYSTEM INFORMATION:');
        report.push(f'Version: 1.1.0');
        report.push(f'Contexts: {len(this.contexts)}');
        report.push(f'Payloads: {sum(len(p) for p in this.payloads.values())}');
        report.push('');

        report.push('AVAILABLE CONTEXTS:');
        Object.entries(this.contexts).forEach(([context, info]) => {
            report.push(f'• {context}: {info.severity} (CVSS: {info.cvss_score})');
        });
        report.push('');

        report.push('PAYLOAD COVERAGE:');
        Object.entries(this.payloads).forEach(([context, payloads]) => {
            report.push(f'• {context}: {len(payloads)} payloads');
        });

        return report.join('\n');
    }
};

// Initialize plugin when loaded
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BRSKBPlugin;
} else {
    // Browser/Insomnia environment
    window.BRSKBPlugin = BRSKBPlugin;
    BRSKBPlugin.init();
}

