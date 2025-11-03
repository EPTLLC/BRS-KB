// BRS-KB Browser Extension - Content Script
// Real-time XSS context detection and payload testing

class BRSKBContentScript {
    constructor() {
        this.observedElements = new Set();
        this.payloads = null;
        this.contexts = null;
        this.init();
    }

    async init() {
        console.log('BRS-KB Content Script initialized');

        // Load BRS-KB data
        await this.loadBRSKBData();

        // Start monitoring input fields
        this.startInputMonitoring();

        // Add context menu
        this.addContextMenu();

        // Listen for messages from popup
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sendResponse);
            return true; // Keep message channel open
        });
    }

    async loadBRSKBData() {
        try {
            const payloadsResponse = await fetch(chrome.runtime.getURL('payloads/payloads.json'));
            const contextsResponse = await fetch(chrome.runtime.getURL('contexts/contexts.json'));

            this.payloads = await payloadsResponse.json();
            this.contexts = await contextsResponse.json();

            console.log(`BRS-KB data loaded: ${Object.keys(this.payloads).length} contexts`);
        } catch (error) {
            console.error('Failed to load BRS-KB data:', error);
        }
    }

    startInputMonitoring() {
        // Monitor existing input fields
        this.monitorInputs();

        // Monitor dynamically added inputs
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.monitorInputsInElement(node);
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    monitorInputs() {
        const inputs = document.querySelectorAll('input, textarea, select, [contenteditable]');
        inputs.forEach(input => this.monitorInput(input));
    }

    monitorInputsInElement(element) {
        const inputs = element.querySelectorAll('input, textarea, select, [contenteditable]');
        inputs.forEach(input => this.monitorInput(input));
    }

    monitorInput(input) {
        if (this.observedElements.has(input)) {
            return;
        }

        this.observedElements.add(input);

        // Add visual indicator
        this.addBRSKBIndicator(input);

        // Monitor input changes
        input.addEventListener('input', () => {
            this.analyzeInputValue(input);
        });

        input.addEventListener('focus', () => {
            this.analyzeInputValue(input);
        });

        // Initial analysis
        this.analyzeInputValue(input);
    }

    addBRSKBIndicator(input) {
        // Add small BRS-KB indicator
        const indicator = document.createElement('div');
        indicator.className = 'brs-kb-indicator';
        indicator.innerHTML = '🔍';
        indicator.title = 'BRS-KB XSS Analysis Active';
        indicator.style.cssText = `
            position: absolute;
            font-size: 10px;
            background: #d32f2f;
            color: white;
            padding: 2px 4px;
            border-radius: 2px;
            margin-left: 5px;
            z-index: 9999;
            pointer-events: none;
        `;

        // Position indicator
        const rect = input.getBoundingClientRect();
        indicator.style.left = (rect.right + window.scrollX) + 'px';
        indicator.style.top = (rect.top + window.scrollY) + 'px';
    }

    analyzeInputValue(input) {
        const value = this.getInputValue(input);

        if (!value || value.length < 3) {
            return;
        }

        // Analyze with BRS-KB
        const analysis = this.analyzeWithBRSKB(value);

        if (analysis.contexts.length > 0) {
            this.showAnalysisResults(input, analysis);
        }
    }

    getInputValue(input) {
        if (input.tagName === 'TEXTAREA' || input.hasAttribute('contenteditable')) {
            return input.textContent || input.innerText || '';
        } else if (input.tagName === 'SELECT') {
            return input.value || '';
        } else {
            return input.value || '';
        }
    }

    analyzeWithBRSKB(value) {
        // Simulate BRS-KB analysis
        const contexts = [];
        let confidence = 0.0;
        let severity = 'low';

        // Check for script patterns
        if (/<script[^>]*>.*?<\/script>/i.test(value)) {
            contexts.push('html_content');
            severity = 'critical';
            confidence = 0.95;
        }

        // Check for event handlers
        if (/on\w+\s*=/i.test(value)) {
            contexts.push('html_attribute');
            severity = 'high';
            confidence = Math.max(confidence, 0.85);
        }

        // Check for JavaScript protocol
        if (/javascript:/i.test(value)) {
            contexts.push('url_context');
            severity = 'high';
            confidence = Math.max(confidence, 0.90);
        }

        // Check for template patterns
        if (/\{\{.*\}\}/.test(value)) {
            contexts.push('template_injection');
            severity = 'critical';
            confidence = Math.max(confidence, 0.98);
        }

        return {
            contexts: contexts,
            severity: severity,
            confidence: confidence,
            suggestions: this.getPayloadSuggestions(contexts)
        };
    }

    getPayloadSuggestions(contexts) {
        const suggestions = [];

        if (contexts.length > 0 && this.payloads) {
            for (const context of contexts.slice(0, 2)) { // Top 2 contexts
                if (this.payloads[context]) {
                    suggestions.push(...this.payloads[context].slice(0, 3));
                }
            }
        }

        return suggestions.slice(0, 5); // Max 5 suggestions
    }

    showAnalysisResults(input, analysis) {
        // Remove existing analysis
        const existingAnalysis = input.parentNode.querySelector('.brs-kb-analysis');
        if (existingAnalysis) {
            existingAnalysis.remove();
        }

        // Create analysis tooltip
        const analysisDiv = document.createElement('div');
        analysisDiv.className = 'brs-kb-analysis';
        analysisDiv.style.cssText = `
            position: absolute;
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 8px;
            font-size: 11px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            z-index: 10000;
            min-width: 200px;
            margin-top: 5px;
        `;

        const rect = input.getBoundingClientRect();
        analysisDiv.style.left = (rect.left + window.scrollX) + 'px';
        analysisDiv.style.top = (rect.bottom + window.scrollY) + 'px';

        // Add content
        let content = `<strong>BRS-KB Analysis</strong><br>`;
        content += `Contexts: ${analysis.contexts.join(', ')}<br>`;
        content += `Severity: <span style="color: #d32f2f;">${analysis.severity.toUpperCase()}</span><br>`;
        content += `Confidence: ${(analysis.confidence * 100).toFixed(1)}%<br>`;

        if (analysis.suggestions.length > 0) {
            content += `<br><strong>Suggestions:</strong><br>`;
            analysis.suggestions.forEach(suggestion => {
                content += `<div style="font-family: monospace; background: #f5f5f5; padding: 2px; margin: 1px 0; border-radius: 2px;">${suggestion.length > 40 ? suggestion.substring(0, 40) + '...' : suggestion}</div>`;
            });
        }

        analysisDiv.innerHTML = content;

        // Add to page
        input.parentNode.appendChild(analysisDiv);

        // Auto-hide after 10 seconds
        setTimeout(() => {
            if (analysisDiv.parentNode) {
                analysisDiv.remove();
            }
        }, 10000);
    }

    addContextMenu() {
        // Add context menu item for selected text
        document.addEventListener('contextmenu', (e) => {
            const selectedText = window.getSelection().toString().trim();

            if (selectedText && selectedText.length > 3) {
                // Send message to background script to add context menu
                chrome.runtime.sendMessage({
                    action: 'add_context_menu',
                    text: selectedText
                });
            }
        });
    }

    handleMessage(message, sendResponse) {
        if (message.action === 'analyze_selected_text') {
            const analysis = this.analyzeWithBRSKB(message.text);
            sendResponse(analysis);
        }
    }
}

// Initialize content script
new BRSKBContentScript();

