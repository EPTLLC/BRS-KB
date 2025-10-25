import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Header from '../components/Header';
import Footer from '../components/Footer';

const Contexts = ({ language }) => {
  const [contexts, setContexts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadContexts();
  }, []);

  const loadContexts = async () => {
    try {
      // Simulate API call to get contexts
      const mockContexts = [
        {
          id: 'html_content',
          title: 'Cross-Site Scripting (XSS) in HTML Content',
          severity: 'critical',
          cvss_score: 8.8,
          description: 'User input is reflected directly into the HTML body without proper sanitization...',
          payload_count: 74
        },
        {
          id: 'websocket_xss',
          title: 'Cross-Site Scripting (XSS) in WebSocket Context',
          severity: 'high',
          cvss_score: 7.5,
          description: 'WebSocket XSS occurs when user input is reflected into WebSocket messages...',
          payload_count: 6
        },
        {
          id: 'service_worker_xss',
          title: 'Cross-Site Scripting (XSS) in Service Worker Context',
          severity: 'high',
          cvss_score: 7.8,
          description: 'Service Worker XSS occurs when user input is reflected into Service Worker scripts...',
          payload_count: 7
        },
        {
          id: 'webrtc_xss',
          title: 'Cross-Site Scripting (XSS) in WebRTC Context',
          severity: 'high',
          cvss_score: 7.6,
          description: 'WebRTC XSS occurs when user input is reflected in WebRTC data channels...',
          payload_count: 6
        },
        {
          id: 'graphql_xss',
          title: 'Cross-Site Scripting (XSS) in GraphQL Context',
          severity: 'high',
          cvss_score: 7.4,
          description: 'GraphQL XSS occurs when user input is reflected in GraphQL queries...',
          payload_count: 6
        },
        {
          id: 'shadow_dom_xss',
          title: 'Cross-Site Scripting (XSS) in Shadow DOM Context',
          severity: 'high',
          cvss_score: 7.3,
          description: 'Shadow DOM XSS occurs when user input is reflected in Shadow DOM elements...',
          payload_count: 7
        },
        {
          id: 'custom_elements_xss',
          title: 'Cross-Site Scripting (XSS) in Custom Elements Context',
          severity: 'high',
          cvss_score: 7.1,
          description: 'Custom Elements XSS occurs when user input is reflected in custom element definitions...',
          payload_count: 7
        },
        {
          id: 'http2_push_xss',
          title: 'Cross-Site Scripting (XSS) in HTTP/2 Push Context',
          severity: 'medium',
          cvss_score: 6.8,
          description: 'HTTP/2 Push XSS occurs when user input is reflected in HTTP/2 push resources...',
          payload_count: 4
        },
        {
          id: 'iframe_sandbox_xss',
          title: 'Cross-Site Scripting (XSS) via iframe Sandbox Bypass',
          severity: 'medium',
          cvss_score: 6.3,
          description: 'iframe Sandbox XSS occurs when sandbox restrictions are bypassed...',
          payload_count: 2
        },
        {
          id: 'indexeddb_xss',
          title: 'Cross-Site Scripting (XSS) in IndexedDB Context',
          severity: 'medium',
          cvss_score: 6.5,
          description: 'IndexedDB XSS occurs when user input is reflected in IndexedDB storage...',
          payload_count: 3
        },
        {
          id: 'webgl_xss',
          title: 'Cross-Site Scripting (XSS) in WebGL Context',
          severity: 'medium',
          cvss_score: 6.1,
          description: 'WebGL XSS occurs when user input is reflected in WebGL shaders...',
          payload_count: 3
        },
        {
          id: 'css_context',
          title: 'Cross-Site Scripting (XSS) in CSS Context',
          severity: 'high',
          cvss_score: 7.5,
          description: 'CSS XSS occurs when user input is reflected in CSS styles...',
          payload_count: 16
        },
        {
          id: 'svg_context',
          title: 'Cross-Site Scripting (XSS) in SVG Context',
          severity: 'high',
          cvss_score: 7.3,
          description: 'SVG XSS occurs when user input is reflected in SVG elements...',
          payload_count: 12
        },
        {
          id: 'markdown_context',
          title: 'Cross-Site Scripting (XSS) in Markdown Context',
          severity: 'medium',
          cvss_score: 6.1,
          description: 'Markdown XSS occurs when user input is reflected in Markdown rendering...',
          payload_count: 4
        },
        {
          id: 'json_value',
          title: 'Cross-Site Scripting (XSS) in JSON Context',
          severity: 'medium',
          cvss_score: 6.1,
          description: 'JSON XSS occurs when user input is reflected in JSON data...',
          payload_count: 1
        },
        {
          id: 'xml_content',
          title: 'Cross-Site Scripting (XSS) in XML Context',
          severity: 'high',
          cvss_score: 7.5,
          description: 'XML XSS occurs when user input is reflected in XML data...',
          payload_count: 3
        },
        {
          id: 'url_context',
          title: 'Cross-Site Scripting (XSS) in URL Context',
          severity: 'high',
          cvss_score: 7.5,
          description: 'URL XSS occurs when user input is reflected in URLs...',
          payload_count: 17
        },
        {
          id: 'dom_xss',
          title: 'DOM-based Cross-Site Scripting (DOM XSS)',
          severity: 'high',
          cvss_score: 7.5,
          description: 'DOM-based XSS occurs when user input is reflected in DOM manipulations...',
          payload_count: 8
        },
        {
          id: 'template_injection',
          title: 'Client-Side Template Injection Leading to XSS',
          severity: 'critical',
          cvss_score: 9.0,
          description: 'Client-Side Template Injection occurs when user input is embedded into client-side templates...',
          payload_count: 12
        },
        {
          id: 'postmessage_xss',
          title: 'PostMessage API XSS Vulnerabilities',
          severity: 'high',
          cvss_score: 7.5,
          description: 'PostMessage XSS occurs when user input is reflected in PostMessage API communications...',
          payload_count: 3
        },
        {
          id: 'wasm_context',
          title: 'WebAssembly Context XSS',
          severity: 'medium',
          cvss_score: 6.1,
          description: 'WebAssembly XSS occurs when user input is reflected in WebAssembly code...',
          payload_count: 3
        },
        {
          id: 'html_attribute',
          title: 'Cross-Site Scripting (XSS) in HTML Attributes',
          severity: 'critical',
          cvss_score: 8.8,
          description: 'HTML Attribute XSS occurs when user input is reflected in HTML tag attributes...',
          payload_count: 12
        },
        {
          id: 'html_comment',
          title: 'Cross-Site Scripting (XSS) in HTML Comments',
          severity: 'medium',
          cvss_score: 6.1,
          description: 'HTML Comment XSS occurs when user input is reflected in HTML comments...',
          payload_count: 6
        },
        {
          id: 'javascript_context',
          title: 'Cross-Site Scripting (XSS) in JavaScript Context',
          severity: 'critical',
          cvss_score: 8.8,
          description: 'JavaScript Context XSS occurs when user input is injected directly into JavaScript code...',
          payload_count: 12
        },
        {
          id: 'js_string',
          title: 'Cross-Site Scripting (XSS) in JavaScript String Context',
          severity: 'critical',
          cvss_score: 8.8,
          description: 'JavaScript String XSS occurs when user input is reflected in JavaScript strings...',
          payload_count: 4
        },
        {
          id: 'js_object',
          title: 'Cross-Site Scripting (XSS) in JavaScript Object Context',
          severity: 'high',
          cvss_score: 7.5,
          description: 'JavaScript Object XSS occurs when user input is reflected in JavaScript objects...',
          payload_count: 1
        }
      ];

      setContexts(mockContexts);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load contexts:', error);
      setLoading(false);
    }
  };

  const filteredContexts = contexts.filter(context => {
    const matchesFilter = filter === 'all' || context.severity === filter;
    const matchesSearch = context.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         context.id.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getSeverityColor = (severity) => {
    const colors = {
      'critical': '#d32f2f',
      'high': '#f57c00',
      'medium': '#fbc02d',
      'low': '#388e3c'
    };
    return colors[severity] || '#666';
  };

  if (loading) {
    return (
      <div>
        <Header currentLanguage={language} darkMode={false} onLanguageChange={() => {}} onToggleDarkMode={() => {}} />
        <div className="container">
          <div className="loading">
            <div className="spinner"></div>
            <p>Loading XSS contexts...</p>
          </div>
        </div>
        <Footer language={language} />
      </div>
    );
  }

  return (
    <div>
      <Header currentLanguage={language} darkMode={false} onLanguageChange={() => {}} onToggleDarkMode={() => {}} />

      <div className="container">
        <div className="page-header">
          <h1>XSS Vulnerability Contexts</h1>
          <p>Explore {contexts.length} different XSS vulnerability contexts with detailed attack vectors and remediation strategies.</p>
        </div>

        <div className="filters">
          <div className="filter-group">
            <label>Filter by Severity:</label>
            <select value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="search-group">
            <label>Search Contexts:</label>
            <input
              type="text"
              placeholder="Search by name or description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
          </div>
        </div>

        <div className="context-stats">
          <div className="stat">
            <span className="stat-number">{contexts.length}</span>
            <span className="stat-label">Total Contexts</span>
          </div>
          <div className="stat">
            <span className="stat-number">{filteredContexts.length}</span>
            <span className="stat-label">Filtered Results</span>
          </div>
          <div className="stat">
            <span className="stat-number">
              {contexts.filter(c => c.severity === 'critical').length}
            </span>
            <span className="stat-label">Critical</span>
          </div>
        </div>

        <div className="context-grid">
          {filteredContexts.map(context => (
            <div key={context.id} className="context-card">
              <div className="context-header">
                <h3 className="context-title">{context.title}</h3>
                <span
                  className={`context-severity severity-${context.severity}`}
                  style={{ backgroundColor: getSeverityColor(context.severity) + '20', color: getSeverityColor(context.severity) }}
                >
                  {context.severity.toUpperCase()}
                </span>
              </div>

              <p className="context-description">
                {context.description.length > 150
                  ? context.description.substring(0, 150) + '...'
                  : context.description}
              </p>

              <div className="context-stats">
                <span className="stat-item">
                  CVSS: {context.cvss_score}
                </span>
                <span className="stat-item">
                  Payloads: {context.payload_count}
                </span>
                <span className="stat-item">
                  ID: {context.id}
                </span>
              </div>

              <div className="context-actions">
                <Link to={`/context/${context.id}`} className="btn btn-primary">View Details</Link>
                <Link to={`/context/${context.id}/test`} className="btn btn-secondary">Test Payloads</Link>
              </div>
            </div>
          ))}
        </div>

        {filteredContexts.length === 0 && (
          <div className="no-results">
            <p>No contexts found matching your criteria.</p>
            <button className="btn btn-primary" onClick={() => {setFilter('all'); setSearchTerm('');}}>
              Clear Filters
            </button>
          </div>
        )}
      </div>

      <Footer language={language} />
    </div>
  );
};

export default Contexts;