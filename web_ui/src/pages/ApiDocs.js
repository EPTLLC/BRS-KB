/**
 * Project: BRS-KB (BRS XSS Knowledge Base)
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: 2025-12-04 22:53:00 UTC
 * Status: Created
 * Telegram: https://t.me/easyprotech
 *
 * API Documentation page component
 */

import React, { useState } from 'react';
import { API_BASE_URL } from '../services/api';

const ApiDocs = ({ language }) => {
  const [activeEndpoint, setActiveEndpoint] = useState(null);

  const endpoints = [
    {
      method: 'GET',
      path: '/api/info',
      description: 'Get system information including version, build, and statistics',
      response: `{
  "version": "2.0.0",
  "build": "2025.10.25",
  "revision": "enhanced",
  "total_contexts": 27,
  "total_payloads": 194,
  "reverse_map_patterns": 29,
  "supported_languages": ["en", "ru", "zh", "es"]
}`,
    },
    {
      method: 'GET',
      path: '/api/contexts',
      description: 'List all available XSS vulnerability contexts',
      response: `{
  "contexts": [
    {
      "id": "html_content",
      "title": "Cross-Site Scripting (XSS) in HTML Content",
      "severity": "critical",
      "cvss_score": 8.8,
      "cwe": ["CWE-79"],
      "owasp": ["A03:2021"]
    }
  ],
  "total": 27
}`,
    },
    {
      method: 'GET',
      path: '/api/contexts/{id}',
      description: 'Get detailed information about a specific context',
      params: [{ name: 'id', type: 'string', description: 'Context identifier (e.g., html_content)' }],
      response: `{
  "id": "html_content",
  "title": "Cross-Site Scripting (XSS) in HTML Content",
  "description": "Detailed vulnerability explanation...",
  "attack_vector": "Real-world attack techniques...",
  "remediation": "Actionable security measures...",
  "severity": "critical",
  "cvss_score": 8.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
  "cwe": ["CWE-79"],
  "owasp": ["A03:2021"],
  "tags": ["xss", "html", "reflected", "stored"]
}`,
    },
    {
      method: 'GET',
      path: '/api/payloads',
      description: 'List payloads with optional filters',
      params: [
        { name: 'context', type: 'string', description: 'Filter by context (optional)' },
        { name: 'severity', type: 'string', description: 'Filter by severity: critical, high, medium, low (optional)' },
        { name: 'waf_bypass', type: 'boolean', description: 'Filter WAF bypass payloads only (optional)' },
        { name: 'limit', type: 'integer', description: 'Limit results (default: 50)' },
        { name: 'offset', type: 'integer', description: 'Offset for pagination (default: 0)' },
      ],
      response: `{
  "payloads": [
    {
      "payload": "<script>alert(1)</script>",
      "contexts": ["html_content", "html_comment"],
      "severity": "critical",
      "cvss_score": 8.8,
      "description": "Basic script tag injection",
      "tags": ["script", "basic"],
      "waf_evasion": false
    }
  ],
  "total": 194,
  "offset": 0,
  "limit": 50
}`,
    },
    {
      method: 'GET',
      path: '/api/payloads/search',
      description: 'Search payloads by query with relevance scoring',
      params: [
        { name: 'q', type: 'string', description: 'Search query (required)' },
        { name: 'limit', type: 'integer', description: 'Limit results (default: 20)' },
      ],
      response: `{
  "results": [
    {
      "payload": "<script>alert(1)</script>",
      "contexts": ["html_content"],
      "severity": "critical",
      "relevance_score": 2.5
    }
  ],
  "query": "script",
  "total": 15
}`,
    },
    {
      method: 'POST',
      path: '/api/analyze',
      description: 'Analyze XSS payload and detect contexts',
      body: `{
  "payload": "<script>alert(1)</script>",
  "ml_features": false
}`,
      response: `{
  "contexts": ["html_content", "websocket_xss"],
  "severity": "critical",
  "confidence": 1.0,
  "defenses": ["html_encoding", "csp", "sanitization"]
}`,
    },
    {
      method: 'GET',
      path: '/api/defenses',
      description: 'Get recommended defenses for a context',
      params: [{ name: 'context', type: 'string', description: 'Context identifier (required)' }],
      response: `{
  "context": "html_content",
  "defenses": [
    {
      "defense": "html_encoding",
      "priority": 1,
      "required": true,
      "tags": ["primary"],
      "effectiveness": { "bypass_difficulty": "high" }
    }
  ]
}`,
    },
    {
      method: 'GET',
      path: '/api/stats',
      description: 'Get platform statistics',
      response: `{
  "total_contexts": 27,
  "total_payloads": 194,
  "severity_distribution": {
    "critical": 20,
    "high": 80,
    "medium": 60,
    "low": 34
  },
  "context_coverage": {
    "html_content": 74,
    "javascript_context": 12
  },
  "waf_bypass_count": 15
}`,
    },
    {
      method: 'GET',
      path: '/api/health',
      description: 'Health check endpoint',
      response: `{
  "status": "healthy",
  "service": "brs-kb-api"
}`,
    },
  ];

  const content = {
    en: {
      title: 'API Documentation',
      subtitle: 'REST API reference for BRS-KB integration',
      baseUrl: 'Base URL',
      endpoints: 'Endpoints',
      parameters: 'Parameters',
      requestBody: 'Request Body',
      response: 'Response',
      tryIt: 'Try it',
    },
    ru: {
      title: 'Документация API',
      subtitle: 'Справочник REST API для интеграции BRS-KB',
      baseUrl: 'Базовый URL',
      endpoints: 'Endpoints',
      parameters: 'Параметры',
      requestBody: 'Тело запроса',
      response: 'Ответ',
      tryIt: 'Попробовать',
    },
  };

  const t = content[language] || content.en;

  const getMethodColor = (method) => {
    const colors = {
      GET: '#61affe',
      POST: '#49cc90',
      PUT: '#fca130',
      DELETE: '#f93e3e',
    };
    return colors[method] || '#666';
  };

  return (
    <div className="api-docs-page">
      <div className="container">
        <div className="page-header">
          <h1>{t.title}</h1>
          <p>{t.subtitle}</p>
        </div>

        <div className="base-url">
          <span className="label">{t.baseUrl}:</span>
          <code>{API_BASE_URL}</code>
        </div>

        <div className="endpoints-list">
          <h2>{t.endpoints}</h2>

          {endpoints.map((endpoint, index) => (
            <div
              key={index}
              className={`endpoint-card ${activeEndpoint === index ? 'expanded' : ''}`}
            >
              <div
                className="endpoint-header"
                onClick={() => setActiveEndpoint(activeEndpoint === index ? null : index)}
              >
                <span
                  className="method"
                  style={{ backgroundColor: getMethodColor(endpoint.method) }}
                >
                  {endpoint.method}
                </span>
                <span className="path">{endpoint.path}</span>
                <span className="description">{endpoint.description}</span>
              </div>

              {activeEndpoint === index && (
                <div className="endpoint-details">
                  {endpoint.params && (
                    <div className="section">
                      <h4>{t.parameters}</h4>
                      <table className="params-table">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Description</th>
                          </tr>
                        </thead>
                        <tbody>
                          {endpoint.params.map((param, i) => (
                            <tr key={i}>
                              <td><code>{param.name}</code></td>
                              <td>{param.type}</td>
                              <td>{param.description}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {endpoint.body && (
                    <div className="section">
                      <h4>{t.requestBody}</h4>
                      <pre className="code-block">{endpoint.body}</pre>
                    </div>
                  )}

                  <div className="section">
                    <h4>{t.response}</h4>
                    <pre className="code-block">{endpoint.response}</pre>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <style jsx>{`
        .api-docs-page {
          padding: 40px 0;
          min-height: 100vh;
        }

        .page-header {
          text-align: center;
          margin-bottom: 40px;
        }

        .page-header h1 {
          font-size: 2.5rem;
          color: #333;
          margin-bottom: 10px;
        }

        .page-header p {
          color: #666;
          font-size: 1.1rem;
        }

        .base-url {
          background: #f5f5f5;
          padding: 15px 20px;
          border-radius: 8px;
          margin-bottom: 30px;
        }

        .base-url .label {
          color: #666;
          margin-right: 10px;
        }

        .base-url code {
          background: #333;
          color: #fff;
          padding: 5px 12px;
          border-radius: 4px;
          font-size: 14px;
        }

        .endpoints-list h2 {
          margin-bottom: 20px;
          color: #333;
        }

        .endpoint-card {
          background: white;
          border-radius: 8px;
          margin-bottom: 10px;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
          overflow: hidden;
        }

        .endpoint-header {
          display: flex;
          align-items: center;
          padding: 15px 20px;
          cursor: pointer;
          transition: background 0.2s;
        }

        .endpoint-header:hover {
          background: #f9f9f9;
        }

        .method {
          color: white;
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
          margin-right: 15px;
          min-width: 60px;
          text-align: center;
        }

        .path {
          font-family: monospace;
          font-size: 14px;
          color: #333;
          margin-right: 20px;
          min-width: 200px;
        }

        .description {
          color: #666;
          font-size: 13px;
        }

        .endpoint-details {
          border-top: 1px solid #eee;
          padding: 20px;
          background: #fafafa;
        }

        .section {
          margin-bottom: 20px;
        }

        .section:last-child {
          margin-bottom: 0;
        }

        .section h4 {
          color: #333;
          margin-bottom: 10px;
          font-size: 14px;
        }

        .params-table {
          width: 100%;
          border-collapse: collapse;
        }

        .params-table th,
        .params-table td {
          text-align: left;
          padding: 10px;
          border-bottom: 1px solid #eee;
        }

        .params-table th {
          background: #f0f0f0;
          font-weight: 600;
          font-size: 13px;
        }

        .params-table td {
          font-size: 13px;
        }

        .params-table code {
          background: #e8e8e8;
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 12px;
        }

        .code-block {
          background: #2d2d2d;
          color: #f8f8f2;
          padding: 15px;
          border-radius: 6px;
          overflow-x: auto;
          font-size: 13px;
          line-height: 1.5;
        }

        @media (max-width: 768px) {
          .endpoint-header {
            flex-wrap: wrap;
            gap: 10px;
          }

          .path {
            min-width: 100%;
            order: 2;
          }

          .description {
            min-width: 100%;
            order: 3;
          }
        }
      `}</style>
    </div>
  );
};

export default ApiDocs;
