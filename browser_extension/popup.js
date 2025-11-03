// BRS-KB Browser Extension - Popup JavaScript
// Advanced XSS context detection and payload testing

class BRSKBPopup {
    constructor() {
        this.currentTab = null;
        this.payloads = null;
        this.contexts = null;
        this.init();
    }

    async init() {
        // Initialize popup
        this.setupEventListeners();
        await this.loadBRSKBData();
        this.updateStatus("BRS-KB extension loaded");
    }

    setupEventListeners() {
        const analyzeBtn = document.getElementById('analyzeBtn');
        const testCurrentPageBtn = document.getElementById('testCurrentPageBtn');
        const clearBtn = document.getElementById('clearBtn');
        const inputField = document.getElementById('inputField');

        analyzeBtn.addEventListener('click', () => this.analyzeInput());
        testCurrentPageBtn.addEventListener('click', () => this.testCurrentPage());
        clearBtn.addEventListener('click', () => this.clearResults());
        inputField.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.analyzeInput();
            }
        });
    }

    async loadBRSKBData() {
        try {
            // Load payloads and contexts from extension resources
            const payloadsResponse = await fetch(chrome.runtime.getURL('payloads/payloads.json'));
            const contextsResponse = await fetch(chrome.runtime.getURL('contexts/contexts.json'));

            this.payloads = await payloadsResponse.json();
            this.contexts = await contextsResponse.json();

            console.log(`Loaded ${Object.keys(this.payloads).length} contexts with payloads`);
        } catch (error) {
            console.error('Failed to load BRS-KB data:', error);
            this.updateStatus("Failed to load BRS-KB data");
        }
    }

    async analyzeInput() {
        const inputText = document.getElementById('inputField').value.trim();

        if (!inputText) {
            this.updateStatus("Enter text to analyze");
            return;
        }

        this.updateStatus("Analyzing...");

        try {
            // Simulate BRS-KB analysis
            const analysis = await this.simulateBRSKBAnalysis(inputText);

            this.displayResults(analysis);
            this.updateStatus(`Analysis complete: ${analysis.contexts.length} contexts detected`);

        } catch (error) {
            console.error('Analysis failed:', error);
            this.updateStatus("Analysis failed");
            this.displayError("Failed to analyze input");
        }
    }

    async testCurrentPage() {
        this.updateStatus("Testing current page...");

        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            const currentTab = tabs[0];

            // Inject test script into current page
            await chrome.scripting.executeScript({
                target: { tabId: currentTab.id },
                function: this.injectTestScript
            });

            this.updateStatus("Test script injected into current page");

        } catch (error) {
            console.error('Failed to test current page:', error);
            this.updateStatus("Failed to test current page");
        }
    }

    async simulateBRSKBAnalysis(inputText) {
        // Simulate BRS-KB analysis logic
        const detectedContexts = [];
        const suggestions = [];

        // Check for script tags
        if (/<script[^>]*>.*?<\/script>/i.test(inputText)) {
            detectedContexts.push({
                name: "html_content",
                severity: "critical",
                confidence: 0.95,
                description: "Script tag injection in HTML content"
            });
            suggestions.push("<script>alert('XSS')</script>");
        }

        // Check for event handlers
        if (/on\w+\s*=/i.test(inputText)) {
            detectedContexts.push({
                name: "html_attribute",
                severity: "high",
                confidence: 0.85,
                description: "Event handler injection"
            });
        }

        // Check for JavaScript protocol
        if (/javascript:/i.test(inputText)) {
            detectedContexts.push({
                name: "url_context",
                severity: "high",
                confidence: 0.90,
                description: "JavaScript protocol injection"
            });
        }

        // Check for template patterns
        if (/\{\{.*\}\}/.test(inputText)) {
            detectedContexts.push({
                name: "template_injection",
                severity: "critical",
                confidence: 0.98,
                description: "Template injection pattern"
            });
        }

        // Get payload suggestions
        if (detectedContexts.length > 0) {
            const primaryContext = detectedContexts[0].name;
            if (this.payloads && this.payloads[primaryContext]) {
                suggestions.push(...this.payloads[primaryContext].slice(0, 3));
            }
        }

        return {
            input: inputText,
            contexts: detectedContexts,
            suggestions: suggestions,
            timestamp: new Date().toISOString()
        };
    }

    displayResults(analysis) {
        const resultsDiv = document.getElementById('results');
        const contextResultsDiv = document.getElementById('contextResults');
        const payloadSuggestionsDiv = document.getElementById('payloadSuggestions');

        // Clear previous results
        contextResultsDiv.innerHTML = '';
        payloadSuggestionsDiv.innerHTML = '';

        // Display detected contexts
        if (analysis.contexts.length > 0) {
            contextResultsDiv.innerHTML = '<h4>🔍 Detected Contexts:</h4>';

            analysis.contexts.forEach(context => {
                const contextDiv = document.createElement('div');
                contextDiv.className = 'result-item context-detected';

                const severityClass = `severity-${context.severity}`;
                contextDiv.innerHTML = `
                    <strong>${context.name}</strong>
                    <span class="${severityClass}">${context.severity.toUpperCase()}</span>
                    <div style="font-size: 10px; margin-top: 3px;">${context.description}</div>
                    <div style="font-size: 10px; color: #666;">Confidence: ${(context.confidence * 100).toFixed(1)}%</div>
                `;

                contextResultsDiv.appendChild(contextDiv);
            });
        }

        // Display payload suggestions
        if (analysis.suggestions.length > 0) {
            payloadSuggestionsDiv.innerHTML = '<h4>💡 Payload Suggestions:</h4>';
            payloadSuggestionsDiv.innerHTML += '<div class="payload-list">';

            analysis.suggestions.forEach(payload => {
                const payloadDiv = document.createElement('div');
                payloadDiv.className = 'payload-item';
                payloadDiv.textContent = payload.length > 50 ? payload.substring(0, 50) + '...' : payload;
                payloadDiv.title = payload;
                payloadDiv.onclick = () => {
                    navigator.clipboard.writeText(payload);
                    this.updateStatus("Payload copied to clipboard");
                };
                payloadSuggestionsDiv.appendChild(payloadDiv);
            });

            payloadSuggestionsDiv.innerHTML += '</div>';
        }

        resultsDiv.style.display = 'block';
    }

    displayError(message) {
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = `<div class="result-item" style="background: #ffebee; border-left: 3px solid #f44336;">❌ ${message}</div>`;
        resultsDiv.style.display = 'block';
    }

    clearResults() {
        document.getElementById('results').style.display = 'none';
        document.getElementById('contextResults').innerHTML = '';
        document.getElementById('payloadSuggestions').innerHTML = '';
        document.getElementById('inputField').value = '';
        this.updateStatus("Ready for analysis");
    }

    updateStatus(message) {
        document.getElementById('statusBar').textContent = message;
    }

    // Test script to inject into current page
    injectTestScript() {
        // This would be the actual test script injected into the page
        console.log('BRS-KB test script injected');
        // In real implementation, this would test for XSS vulnerabilities
    }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new BRSKBPopup();
});

