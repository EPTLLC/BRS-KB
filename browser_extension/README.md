# BRS-KB Browser Extension

Advanced XSS vulnerability detection and payload testing browser extension using BRS-KB intelligence.

## Features

### Real-time XSS Detection
- **Inline context detection** for input fields and forms
- **Visual indicators** for potentially vulnerable elements
- **Automatic analysis** of user input in real-time
- **Context-aware suggestions** based on detected patterns

### Payload Analysis
- **27 XSS contexts** supported
- **200+ categorized payloads** for testing
- **Confidence scoring** for detection accuracy
- **Browser compatibility** validation

### Security Testing
- **Context-specific payload suggestions**
- **WAF bypass technique detection**
- **Framework-aware analysis** (React, Vue, Angular)
- **Real-time vulnerability assessment**

### Integration Features
- **Context menu integration** for selected text analysis
- **Cross-tab communication** for coordinated testing
- **Export capabilities** for security reports
- **Professional security workflow support**

## Installation

### Chrome/Edge
1. Download the extension files
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked" and select the `browser_extension` folder
5. The extension will appear in your toolbar

### Firefox
1. Go to `about:debugging`
2. Click "This Firefox" in the left sidebar
3. Click "Load Temporary Add-on..."
4. Select the `browser_extension/manifest.json` file
5. The extension will be loaded temporarily

## Usage

### Basic Operation
1. **Navigate to any website** with forms or input fields
2. **Look for red indicators** next to input fields
3. **Enter potentially malicious content** to see analysis
4. **Click the extension icon** for detailed analysis
5. **Use context menu** on selected text for quick analysis

### Advanced Features
- **Real-time monitoring** of all input fields
- **Context detection** for different XSS types
- **Payload suggestions** based on detected context
- **Severity assessment** with CVSS scoring
- **Export results** for security reports

### Keyboard Shortcuts
- **Ctrl+Shift+B** - Toggle BRS-KB analysis on current page
- **Ctrl+Shift+C** - Clear all analysis indicators
- **Ctrl+Shift+E** - Export current analysis results

## Configuration

### Extension Settings
Access extension settings through:
- Chrome: Extension options page
- Firefox: Add-on preferences

### Available Options
- **Auto-analysis**: Enable/disable automatic input analysis
- **Visual indicators**: Show/hide red indicators
- **Context sensitivity**: Adjust detection sensitivity
- **Export format**: Choose between JSON/HTML/PDF

### Custom Payloads
Add custom payloads through the options page:
```json
{
 "name": "Custom XSS",
 "payload": "<script>custom_attack()</script>",
 "contexts": ["html_content"],
 "severity": "high"
}
```

## Security Considerations

### Privacy
- **No data collection** - All analysis happens locally
- **No external requests** - Completely offline operation
- **No tracking** - No analytics or telemetry

### Performance
- **Minimal overhead** - Optimized for fast analysis
- **Memory efficient** - Smart cleanup of analysis data
- **Background operation** - Non-blocking UI interactions

### Security
- **Safe execution** - No code injection into analyzed pages
- **Isolated analysis** - Extension runs in isolated environment
- **No cross-site requests** - Respects CORS and security boundaries

## Troubleshooting

### Common Issues

**Extension not loading:**
- Check browser console for errors
- Verify manifest.json syntax
- Ensure all files are in the correct structure

**Analysis not working:**
- Check that the page is fully loaded
- Verify input fields are visible
- Check browser console for JavaScript errors

**Performance issues:**
- Disable auto-analysis for heavy pages
- Clear browser cache
- Restart the extension

### Debug Mode
Enable debug logging:
```javascript
// In popup.js, set DEBUG = true
const DEBUG = true;
```

### Support

For extension-specific issues:
- Check browser extension documentation
- Review console errors
- Test with minimal reproduction

For BRS-KB integration issues:
- Check GitHub Issues: https://github.com/EPTLLC/BRS-KB/issues
- Contact: https://t.me/easyprotech

## Development

### Building from Source
```bash
# Clone repository
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB/browser_extension

# Install dependencies (if any)
npm install # For future build process

# Build extension
# (Currently no build process needed)
```

### Testing
```bash
# Load extension in browser
# Test with various websites
# Check console for errors
```

### Contributing
1. Fork the repository
2. Create feature branch
3. Modify extension files
4. Test thoroughly
5. Submit pull request

## Architecture

```
browser_extension/
 manifest.json # Extension configuration
 popup.html # Extension popup interface
 popup.js # Popup functionality
 content.js # Page content analysis
 content.css # Content script styling
 background.js # Background coordination
 payloads/ # BRS-KB payload data
 payloads.json
 contexts/ # BRS-KB context data
 contexts.json
 icons/ # Extension icons
 icon16.png/svg
 icon32.png/svg
 icon48.png/svg
 icon128.png/svg
```

## Browser Compatibility

| Browser | Version | Status |
|---------|---------|---------|
| Chrome | 88+ | Full Support |
| Firefox | 85+ | Full Support |
| Edge | 88+ | Full Support |
| Safari | 14+ | Limited Support |

## Version History

### v1.0.0
- Initial release with basic XSS detection
- 17 XSS contexts support
- Real-time input analysis

### v2.0.0 (Current)
- Enhanced with 27 XSS contexts
- Improved payload suggestions
- Better UI/UX
- Performance optimizations

## License

**MIT License** - Same as BRS-KB

---

**BRS-KB Browser Extension** 
**Professional XSS detection for web developers and security researchers**

