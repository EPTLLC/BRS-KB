// BRS-KB Browser Extension - Background Script
// Coordination and message handling

chrome.runtime.onInstalled.addListener((details) => {
    console.log('BRS-KB Extension installed/updated');

    if (details.reason === 'install') {
        console.log('BRS-KB Extension installed for the first time');
    } else if (details.reason === 'update') {
        console.log('BRS-KB Extension updated');
    }
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'analyze_selected_text') {
        // Forward to content script for analysis
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, message, (response) => {
                    sendResponse(response);
                });
            }
        });
        return true; // Keep message channel open
    }

    if (message.action === 'add_context_menu') {
        // Add context menu for selected text analysis
        chrome.contextMenus.create({
            id: 'brs_kb_analyze',
            title: 'Analyze with BRS-KB',
            contexts: ['selection']
        });
    }

    return false;
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'brs_kb_analyze' && info.selectionText) {
        // Analyze selected text
        const selectedText = info.selectionText;

        chrome.tabs.sendMessage(tab.id, {
            action: 'analyze_selected_text',
            text: selectedText
        }, (response) => {
            if (response && response.contexts) {
                // Show notification with results
                const contextCount = response.contexts.length;
                const severity = response.severity;

                chrome.notifications.create('brs_kb_analysis', {
                    type: 'basic',
                    iconUrl: 'icons/icon128.png',
                    title: 'BRS-KB Analysis Complete',
                    message: `Detected ${contextCount} XSS context(s) with ${severity} severity`
                });
            }
        });
    }
});

// Handle tab updates for dynamic content detection
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Inject content script into new tabs
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            files: ['content.js']
        }).catch(error => {
            console.log('Content script injection failed:', error);
        });
    }
});

// Clean up on extension unload
chrome.runtime.onSuspend.addListener(() => {
    console.log('BRS-KB Extension suspending');
});

// Error handling
chrome.runtime.onError.addListener((error) => {
    console.error('BRS-KB Extension error:', error);
});

