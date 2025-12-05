/**
 * Project: BRS-KB (BRS XSS Knowledge Base)
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: 2025-12-04 22:53:00 UTC
 * Status: Created
 * Telegram: https://t.me/easyprotech
 *
 * Playground page component - Interactive payload testing
 */

import React, { useState } from 'react';
import api from '../services/api';

const Playground = ({ language }) => {
  const [payload, setPayload] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [mlFeatures, setMlFeatures] = useState(false);

  const analyzePayload = async () => {
    if (!payload.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const data = await api.analyzePayloadPost(payload, mlFeatures);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#d32f2f',
      high: '#f57c00',
      medium: '#fbc02d',
      low: '#388e3c',
    };
    return colors[severity] || '#666';
  };

  const examplePayloads = [
    { name: 'Basic Script', payload: '<script>alert(1)</script>' },
    { name: 'Event Handler', payload: '<img src=x onerror=alert(1)>' },
    { name: 'SVG Onload', payload: '<svg onload=alert(1)>' },
    { name: 'JavaScript Protocol', payload: 'javascript:alert(document.cookie)' },
    { name: 'Template Injection', payload: '{{constructor.constructor("alert(1)")()}}' },
    { name: 'DOM XSS', payload: 'location.hash.substr(1)' },
  ];

  const content = {
    en: {
      title: 'XSS Payload Analyzer',
      subtitle: 'Test and analyze XSS payloads in real-time',
      placeholder: 'Enter your XSS payload here...',
      analyze: 'Analyze Payload',
      analyzing: 'Analyzing...',
      examples: 'Example Payloads',
      results: 'Analysis Results',
      contexts: 'Detected Contexts',
      severity: 'Severity',
      confidence: 'Confidence',
      defenses: 'Recommended Defenses',
      features: 'ML Features',
      mlToggle: 'Include ML Features',
    },
    ru: {
      title: 'Анализатор XSS Payloads',
      subtitle: 'Тестируйте и анализируйте XSS payloads в реальном времени',
      placeholder: 'Введите ваш XSS payload здесь...',
      analyze: 'Анализировать',
      analyzing: 'Анализ...',
      examples: 'Примеры Payloads',
      results: 'Результаты анализа',
      contexts: 'Обнаруженные контексты',
      severity: 'Серьезность',
      confidence: 'Уверенность',
      defenses: 'Рекомендуемые защиты',
      features: 'ML Признаки',
      mlToggle: 'Включить ML признаки',
    },
  };

  const t = content[language] || content.en;

  return (
    <div className="playground-page">
      <div className="container">
        <div className="page-header">
          <h1>{t.title}</h1>
          <p>{t.subtitle}</p>
        </div>

        <div className="playground-content">
          <div className="input-section">
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder={t.placeholder}
              rows={6}
            />

            <div className="controls">
              <label className="ml-toggle">
                <input
                  type="checkbox"
                  checked={mlFeatures}
                  onChange={(e) => setMlFeatures(e.target.checked)}
                />
                {t.mlToggle}
              </label>

              <button
                onClick={analyzePayload}
                disabled={loading || !payload.trim()}
                className="analyze-btn"
              >
                {loading ? t.analyzing : t.analyze}
              </button>
            </div>

            <div className="examples">
              <h3>{t.examples}</h3>
              <div className="example-buttons">
                {examplePayloads.map((example, index) => (
                  <button
                    key={index}
                    onClick={() => setPayload(example.payload)}
                    className="example-btn"
                  >
                    {example.name}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="results-section">
            {error && (
              <div className="error-message">
                Error: {error}
              </div>
            )}

            {result && (
              <div className="results">
                <h3>{t.results}</h3>

                <div className="result-card">
                  <div className="result-header">
                    <span
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(result.severity) }}
                    >
                      {result.severity?.toUpperCase()}
                    </span>
                    {result.confidence && (
                      <span className="confidence">
                        {t.confidence}: {(result.confidence * 100).toFixed(0)}%
                      </span>
                    )}
                  </div>

                  <div className="result-section">
                    <h4>{t.contexts}</h4>
                    <div className="context-list">
                      {result.contexts?.map((ctx, index) => (
                        <span key={index} className="context-badge">
                          {ctx}
                        </span>
                      ))}
                    </div>
                  </div>

                  {result.defenses && (
                    <div className="result-section">
                      <h4>{t.defenses}</h4>
                      <ul className="defense-list">
                        {result.defenses?.map((defense, index) => (
                          <li key={index}>{defense}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {mlFeatures && result.features && (
                    <div className="result-section">
                      <h4>{t.features}</h4>
                      <div className="features-grid">
                        {Object.entries(result.features).map(([key, value]) => (
                          <div key={key} className="feature-item">
                            <span className="feature-key">{key}:</span>
                            <span className="feature-value">
                              {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {!result && !error && (
              <div className="placeholder">
                Enter a payload and click Analyze to see results
              </div>
            )}
          </div>
        </div>
      </div>

      <style jsx>{`
        .playground-page {
          padding: 40px 0;
          min-height: 100vh;
          background: #f5f5f5;
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

        .playground-content {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 30px;
        }

        .input-section {
          background: white;
          padding: 30px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        textarea {
          width: 100%;
          padding: 15px;
          border: 2px solid #ddd;
          border-radius: 8px;
          font-family: monospace;
          font-size: 14px;
          resize: vertical;
        }

        textarea:focus {
          outline: none;
          border-color: #d32f2f;
        }

        .controls {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-top: 15px;
        }

        .ml-toggle {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
        }

        .analyze-btn {
          padding: 12px 30px;
          background: #d32f2f;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
        }

        .analyze-btn:hover {
          background: #b71c1c;
        }

        .analyze-btn:disabled {
          background: #ccc;
          cursor: not-allowed;
        }

        .examples {
          margin-top: 30px;
        }

        .examples h3 {
          margin-bottom: 15px;
          color: #333;
        }

        .example-buttons {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
        }

        .example-btn {
          padding: 8px 16px;
          background: #f5f5f5;
          border: 1px solid #ddd;
          border-radius: 6px;
          cursor: pointer;
          font-size: 13px;
          transition: all 0.2s;
        }

        .example-btn:hover {
          background: #e0e0e0;
          border-color: #999;
        }

        .results-section {
          background: white;
          padding: 30px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .error-message {
          background: #ffebee;
          color: #c62828;
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 20px;
        }

        .results h3 {
          margin-bottom: 20px;
          color: #333;
        }

        .result-card {
          background: #fafafa;
          padding: 20px;
          border-radius: 8px;
        }

        .result-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }

        .severity-badge {
          color: white;
          padding: 6px 16px;
          border-radius: 6px;
          font-weight: 600;
          font-size: 14px;
        }

        .confidence {
          color: #666;
          font-weight: 500;
        }

        .result-section {
          margin-bottom: 20px;
        }

        .result-section h4 {
          color: #333;
          margin-bottom: 10px;
          font-size: 14px;
        }

        .context-list {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }

        .context-badge {
          background: #e3f2fd;
          color: #1976d2;
          padding: 6px 14px;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 500;
        }

        .defense-list {
          list-style: none;
          padding: 0;
          margin: 0;
        }

        .defense-list li {
          padding: 8px 0;
          border-bottom: 1px solid #eee;
          color: #666;
        }

        .defense-list li:last-child {
          border-bottom: none;
        }

        .features-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 10px;
        }

        .feature-item {
          display: flex;
          justify-content: space-between;
          padding: 8px;
          background: white;
          border-radius: 4px;
          font-size: 13px;
        }

        .feature-key {
          color: #666;
        }

        .feature-value {
          font-weight: 600;
          color: #333;
        }

        .placeholder {
          text-align: center;
          color: #999;
          padding: 60px;
        }

        @media (max-width: 1024px) {
          .playground-content {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  );
};

export default Playground;
