/**
 * Project: BRS-KB (BRS XSS Knowledge Base)
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: 2025-12-04 22:53:00 UTC
 * Status: Created
 * Telegram: https://t.me/easyprotech
 *
 * Payloads page component
 */

import React, { useState, useEffect } from 'react';
import api from '../services/api';

const Payloads = ({ language }) => {
  const [payloads, setPayloads] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState({
    context: '',
    severity: '',
    wafBypass: false,
  });
  const [pagination, setPagination] = useState({
    offset: 0,
    limit: 20,
    total: 0,
  });

  useEffect(() => {
    loadPayloads();
  }, [filter, pagination.offset]);

  const loadPayloads = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {
        limit: pagination.limit,
        offset: pagination.offset,
      };
      if (filter.context) params.context = filter.context;
      if (filter.severity) params.severity = filter.severity;
      if (filter.wafBypass) params.waf_bypass = 'true';

      const data = await api.listPayloads(params);
      setPayloads(data.payloads);
      setPagination(prev => ({ ...prev, total: data.total }));
    } catch (err) {
      setError(err.message);
      // Fallback to empty array if API not available
      setPayloads([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      loadPayloads();
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await api.searchPayloads(searchQuery, 50);
      setPayloads(data.results);
      setPagination(prev => ({ ...prev, total: data.total }));
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

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const content = {
    en: {
      title: 'XSS Payloads Database',
      subtitle: 'Browse and search through 200+ categorized XSS payloads',
      search: 'Search payloads...',
      filters: 'Filters',
      context: 'Context',
      severity: 'Severity',
      wafBypass: 'WAF Bypass Only',
      all: 'All',
      copy: 'Copy',
      tags: 'Tags',
      browsers: 'Browsers',
      noResults: 'No payloads found',
    },
    ru: {
      title: 'База данных XSS Payloads',
      subtitle: 'Просмотр и поиск среди 200+ категоризированных XSS payloads',
      search: 'Поиск payloads...',
      filters: 'Фильтры',
      context: 'Контекст',
      severity: 'Серьезность',
      wafBypass: 'Только WAF Bypass',
      all: 'Все',
      copy: 'Копировать',
      tags: 'Теги',
      browsers: 'Браузеры',
      noResults: 'Payloads не найдены',
    },
  };

  const t = content[language] || content.en;

  return (
    <div className="payloads-page">
      <div className="container">
        <div className="page-header">
          <h1>{t.title}</h1>
          <p>{t.subtitle}</p>
        </div>

        <div className="controls">
          <div className="search-box">
            <input
              type="text"
              placeholder={t.search}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            />
            <button onClick={handleSearch}>Search</button>
          </div>

          <div className="filters">
            <select
              value={filter.severity}
              onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
            >
              <option value="">{t.all} {t.severity}</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={filter.wafBypass}
                onChange={(e) => setFilter({ ...filter, wafBypass: e.target.checked })}
              />
              {t.wafBypass}
            </label>
          </div>
        </div>

        {error && (
          <div className="error-message">
            API Error: {error}. Showing cached data.
          </div>
        )}

        {loading ? (
          <div className="loading">Loading payloads...</div>
        ) : (
          <>
            <div className="results-info">
              Showing {payloads.length} of {pagination.total} payloads
            </div>

            <div className="payloads-grid">
              {payloads.map((payload, index) => (
                <div key={index} className="payload-card">
                  <div className="payload-header">
                    <span
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(payload.severity) }}
                    >
                      {payload.severity}
                    </span>
                    <span className="cvss">CVSS: {payload.cvss_score}</span>
                  </div>

                  <div className="payload-content">
                    <pre>{payload.payload}</pre>
                    <button
                      className="copy-btn"
                      onClick={() => copyToClipboard(payload.payload)}
                    >
                      {t.copy}
                    </button>
                  </div>

                  <p className="description">{payload.description}</p>

                  <div className="payload-meta">
                    <div className="contexts">
                      {payload.contexts?.map((ctx, i) => (
                        <span key={i} className="context-tag">{ctx}</span>
                      ))}
                    </div>
                    <div className="tags">
                      {payload.tags?.slice(0, 3).map((tag, i) => (
                        <span key={i} className="tag">{tag}</span>
                      ))}
                    </div>
                  </div>

                  {payload.waf_evasion && (
                    <div className="waf-badge">WAF Bypass</div>
                  )}
                </div>
              ))}
            </div>

            {payloads.length === 0 && (
              <div className="no-results">{t.noResults}</div>
            )}

            {pagination.total > pagination.limit && (
              <div className="pagination">
                <button
                  disabled={pagination.offset === 0}
                  onClick={() => setPagination({ ...pagination, offset: pagination.offset - pagination.limit })}
                >
                  Previous
                </button>
                <span>
                  Page {Math.floor(pagination.offset / pagination.limit) + 1} of{' '}
                  {Math.ceil(pagination.total / pagination.limit)}
                </span>
                <button
                  disabled={pagination.offset + pagination.limit >= pagination.total}
                  onClick={() => setPagination({ ...pagination, offset: pagination.offset + pagination.limit })}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>

      <style jsx>{`
        .payloads-page {
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

        .controls {
          display: flex;
          gap: 20px;
          margin-bottom: 30px;
          flex-wrap: wrap;
        }

        .search-box {
          display: flex;
          flex: 1;
          min-width: 300px;
        }

        .search-box input {
          flex: 1;
          padding: 12px 16px;
          border: 2px solid #ddd;
          border-radius: 8px 0 0 8px;
          font-size: 16px;
        }

        .search-box button {
          padding: 12px 24px;
          background: #d32f2f;
          color: white;
          border: none;
          border-radius: 0 8px 8px 0;
          cursor: pointer;
        }

        .filters {
          display: flex;
          gap: 15px;
          align-items: center;
        }

        .filters select {
          padding: 12px 16px;
          border: 2px solid #ddd;
          border-radius: 8px;
          font-size: 14px;
        }

        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
        }

        .error-message {
          background: #fff3cd;
          color: #856404;
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 20px;
        }

        .results-info {
          color: #666;
          margin-bottom: 20px;
        }

        .payloads-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
          gap: 20px;
        }

        .payload-card {
          background: white;
          border-radius: 12px;
          padding: 20px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .payload-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 15px;
        }

        .severity-badge {
          color: white;
          padding: 4px 12px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
        }

        .cvss {
          font-weight: 600;
          color: #666;
        }

        .payload-content {
          position: relative;
          margin-bottom: 15px;
        }

        .payload-content pre {
          background: #f5f5f5;
          padding: 15px;
          border-radius: 8px;
          overflow-x: auto;
          font-size: 13px;
          margin: 0;
        }

        .copy-btn {
          position: absolute;
          top: 8px;
          right: 8px;
          padding: 4px 10px;
          background: #333;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 12px;
          cursor: pointer;
          opacity: 0.8;
        }

        .copy-btn:hover {
          opacity: 1;
        }

        .description {
          color: #666;
          font-size: 14px;
          margin-bottom: 15px;
        }

        .payload-meta {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
        }

        .contexts {
          display: flex;
          flex-wrap: wrap;
          gap: 5px;
        }

        .context-tag {
          background: #e3f2fd;
          color: #1976d2;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 12px;
        }

        .tags {
          display: flex;
          flex-wrap: wrap;
          gap: 5px;
        }

        .tag {
          background: #f5f5f5;
          color: #666;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 12px;
        }

        .waf-badge {
          margin-top: 10px;
          display: inline-block;
          background: #ff9800;
          color: white;
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
        }

        .pagination {
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 20px;
          margin-top: 40px;
        }

        .pagination button {
          padding: 10px 20px;
          background: #d32f2f;
          color: white;
          border: none;
          border-radius: 8px;
          cursor: pointer;
        }

        .pagination button:disabled {
          background: #ccc;
          cursor: not-allowed;
        }

        .loading, .no-results {
          text-align: center;
          padding: 60px;
          color: #666;
        }

        @media (max-width: 768px) {
          .controls {
            flex-direction: column;
          }

          .search-box {
            min-width: 100%;
          }

          .payloads-grid {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  );
};

export default Payloads;
