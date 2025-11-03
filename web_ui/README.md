# BRS-KB Web UI

Modern React-based web interface for BRS-KB XSS Knowledge Base.

## Features

### Modern Interface
- **Responsive design** - Works on desktop, tablet, and mobile
- **Dark/Light mode** - Theme switching capability
- **Multi-language support** - English, Russian, Chinese, Spanish
- **Professional UI/UX** - Clean, modern design with accessibility

### Interactive Exploration
- **Context browser** - Visual exploration of 27 XSS contexts
- **Payload database** - Interactive payload search and filtering
- **Real-time analysis** - Live payload testing and validation
- **Statistics dashboard** - Visual metrics and analytics

### Security Testing
- **Playground interface** - Safe testing environment for payloads
- **Context detection** - Automatic identification of XSS types
- **Browser integration** - Direct testing in web browsers
- **Export capabilities** - Generate security reports

### Multi-Language Support
- **4 languages** - Complete localization
- **Cultural adaptation** - Region-specific content
- **Professional translation** - Enterprise-grade translations
- **Language switching** - Real-time language changes

## Technology Stack

### Frontend
- **React 18** - Modern React with hooks
- **React Router** - Client-side routing
- **Chart.js** - Data visualization
- **Monaco Editor** - Code editor integration
- **Prism.js** - Syntax highlighting

### Styling
- **CSS3** - Modern CSS with flexbox/grid
- **Responsive design** - Mobile-first approach
- **Dark mode support** - Complete theme system
- **Accessibility** - WCAG compliant

### Build Tools
- **Create React App** - Zero-configuration setup
- **Babel** - JavaScript transpilation
- **Webpack** - Module bundling
- **ESLint** - Code linting

## Installation

### Prerequisites
```bash
# Node.js 16+ and npm
node --version # Should be 16+
npm --version # Should be 8+
```

### Setup
```bash
# Navigate to web UI directory
cd web_ui

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build

# Deploy to GitHub Pages (optional)
npm run deploy
```

### Development
```bash
# Start development server
npm start

# Run tests
npm test

# Run tests with coverage
npm test -- --coverage

# Build for production
npm run build
```

## Configuration

### Environment Variables
Create `.env` file in web_ui directory:

```env
# API Configuration
REACT_APP_API_URL=https://api.brs-kb.com
REACT_APP_API_KEY=your-api-key

# Feature Flags
REACT_APP_ENABLE_ANALYTICS=false
REACT_APP_ENABLE_ERROR_REPORTING=true

# Localization
REACT_APP_DEFAULT_LANGUAGE=en
REACT_APP_SUPPORTED_LANGUAGES=en,ru,zh,es
```

### Localization Setup
1. Add translation files to `src/locales/`
2. Configure supported languages in `src/config/languages.js`
3. Use translation hooks in components

## Usage

### Basic Navigation
- **Home** - Platform overview and features
- **Contexts** - Browse 27 XSS vulnerability contexts
- **Payloads** - Search and analyze payload database
- **Playground** - Test payloads in safe environment
- **Dashboard** - Statistics and analytics
- **API Docs** - Complete API reference

### Advanced Features
- **Real-time analysis** - Live payload testing
- **Context detection** - Automatic XSS type identification
- **Export functionality** - Generate security reports
- **Language switching** - Multi-language interface

### Keyboard Shortcuts
- **Ctrl/Cmd + K** - Toggle command palette
- **Ctrl/Cmd + D** - Toggle dark mode
- **Ctrl/Cmd + L** - Change language
- **Esc** - Close modals and dialogs

## API Integration

### Backend Communication
```javascript
// Example API call
const response = await fetch('/api/brs-kb/analyze', {
 method: 'POST',
 headers: {
 'Content-Type': 'application/json',
 },
 body: JSON.stringify({
 payload: '<script>alert(1)</script>',
 context: 'html_content'
 })
});

const result = await response.json();
```

### Real-time Updates
```javascript
// WebSocket connection for live updates
const ws = new WebSocket('wss://api.brs-kb.com/ws');

ws.onmessage = (event) => {
 const data = JSON.parse(event.data);
 // Update UI with new analysis results
};
```

## Customization

### Theme Customization
Edit `src/styles/themes.js`:

```javascript
export const themes = {
 light: {
 primary: '#d32f2f',
 secondary: '#f5f5f5',
 background: '#ffffff',
 text: '#333333'
 },
 dark: {
 primary: '#d32f2f',
 secondary: '#2d2d2d',
 background: '#1a1a1a',
 text: '#e0e0e0'
 }
};
```

### Component Customization
```javascript
// Custom context card component
const CustomContextCard = ({ context }) => {
 return (
 <div className="custom-context-card">
 <h3>{context.title}</h3>
 <p>{context.description}</p>
 <div className="custom-actions">
 <button>Analyze</button>
 <button>Test</button>
 </div>
 </div>
 );
};
```

## Development

### Code Structure
```
web_ui/
 public/ # Static assets
 index.html # Main HTML template
 favicon.ico # Site icon
 robots.txt # SEO file
 src/
 components/ # Reusable React components
 Header.js # Navigation header
 Footer.js # Site footer
 ...
 pages/ # Route components
 Home.js # Landing page
 Contexts.js # Context browser
 ...
 styles/ # CSS files
 index.css # Global styles
 App.css # App-specific styles
 ...
 utils/ # Utility functions
 api.js # API communication
 helpers.js # Helper functions
 ...
 locales/ # Translation files
 en.json # English translations
 ru.json # Russian translations
 ...
 App.js # Main application component
 index.js # React entry point
 package.json # Dependencies and scripts
```

### Adding New Components
1. Create component in `src/components/`
2. Import and use in relevant pages
3. Add styles in `src/styles/`
4. Add tests in `src/__tests__/`

### Localization
1. Add translations to `src/locales/`
2. Use translation hooks in components
3. Test with different languages

## Testing

### Unit Tests
```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run specific test
npm test ContextCard.test.js
```

### Integration Tests
```bash
# Test API integration
npm test -- --testPathPattern=integration

# Test with coverage
npm test -- --coverage
```

### E2E Tests
```bash
# Install Cypress
npm install -D cypress

# Run E2E tests
npx cypress run
```

## Deployment

### Development
```bash
# Start development server
npm start

# Server runs on http://localhost:3000
```

### Production Build
```bash
# Create optimized production build
npm run build

# Build outputs to build/ directory
```

### GitHub Pages
```bash
# Deploy to GitHub Pages
npm run deploy

# Requires gh-pages package and homepage URL in package.json
```

### Docker Deployment
```dockerfile
FROM node:16-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## Performance

### Optimization Features
- **Code splitting** - Lazy loading of components
- **Image optimization** - WebP format support
- **Bundle analysis** - Webpack bundle analyzer
- **Caching** - Service worker for offline support

### Performance Metrics
- **Lighthouse score** - 95+ for all categories
- **First Contentful Paint** - < 1.5s
- **Largest Contentful Paint** - < 2.5s
- **Cumulative Layout Shift** - < 0.1

### Monitoring
```javascript
// Performance monitoring
if ('performance' in window) {
 window.addEventListener('load', () => {
 const perfData = performance.getEntriesByType('navigation')[0];
 console.log('Page load time:', perfData.loadEventEnd - perfData.fetchStart);
 });
}
```

## Browser Support

| Browser | Version | Status |
|---------|---------|---------|
| Chrome | 88+ | Full Support |
| Firefox | 85+ | Full Support |
| Safari | 14+ | Full Support |
| Edge | 88+ | Full Support |

## Accessibility

### WCAG Compliance
- **AA level** - Meets Web Content Accessibility Guidelines
- **Keyboard navigation** - Full keyboard support
- **Screen reader** - ARIA labels and semantic HTML
- **Color contrast** - 4.5:1 minimum ratio

### Features
- **High contrast mode** - Enhanced visibility
- **Reduced motion** - Respects user preferences
- **Focus indicators** - Clear visual focus
- **Alternative text** - Descriptive image alt text

## Security

### Content Security Policy
```html
<meta http-equiv="Content-Security-Policy" content="
 default-src 'self';
 script-src 'self' 'unsafe-inline';
 style-src 'self' 'unsafe-inline';
 img-src 'self' data: https:;
 connect-src 'self' https://api.brs-kb.com;
">
```

### Security Headers
- **X-Frame-Options** - Prevent clickjacking
- **X-Content-Type-Options** - Prevent MIME sniffing
- **Strict-Transport-Security** - Force HTTPS
- **Content-Security-Policy** - XSS protection

## Troubleshooting

### Common Issues

**Build fails:**
- Check Node.js version (16+ required)
- Clear npm cache: `npm cache clean --force`
- Delete node_modules and reinstall

**Runtime errors:**
- Check browser console for errors
- Verify API endpoints are accessible
- Check network connectivity

**Styling issues:**
- Clear browser cache
- Check CSS imports
- Verify theme configuration

### Debug Mode
Enable debug logging:
```javascript
// Add to App.js
if (process.env.NODE_ENV === 'development') {
 console.log('Debug mode enabled');
}
```

### Support

For Web UI issues:
- Check browser developer tools
- Review console errors
- Test in different browsers

For BRS-KB integration:
- Verify API endpoints
- Check authentication
- Review network requests

## Contributing

### Development Setup
1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/BRS-KB.git`
3. Navigate to web UI: `cd web_ui`
4. Install dependencies: `npm install`
5. Start development: `npm start`

### Adding Features
1. Create feature branch: `git checkout -b feature/new-component`
2. Add component to `src/components/`
3. Add styles to `src/styles/`
4. Add tests to `src/__tests__/`
5. Update documentation
6. Submit pull request

### Code Standards
- **ESLint** - Code linting
- **Prettier** - Code formatting
- **Husky** - Git hooks
- **Conventional commits** - Commit message format

## Version History

### v1.0.0
- Initial React application
- Basic context browsing
- Payload testing interface

### v2.0.0 (Current)
- Enhanced UI/UX design
- Multi-language support
- Advanced analytics
- Performance optimizations

## License

**MIT License** - Same as BRS-KB

---

**BRS-KB Web UI** 
**Modern React interface for XSS intelligence platform**

