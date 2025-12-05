/**
 * Project: BRS-KB (BRS XSS Knowledge Base)
 * Company: EasyProTech LLC (www.easypro.tech)
 * Dev: Brabus
 * Date: 2025-12-04 22:53:00 UTC
 * Status: Created
 * Telegram: https://t.me/easyprotech
 *
 * Dashboard page component - Statistics and overview
 */

import React, { useState, useEffect } from 'react';
import api from '../services/api';

const Dashboard = ({ language }) => {
  const [stats, setStats] = useState(null);
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, infoData] = await Promise.all([
        api.getStats(),
        api.getInfo(),
      ]);
      setStats(statsData);
      setInfo(infoData);
    } catch (err) {
      setError(err.message);
      // Set fallback data
      setStats({
        total_contexts: 27,
        total_payloads: 194,
        severity_distribution: { critical: 20, high: 80, medium: 60, low: 34 },
        waf_bypass_count: 15,
      });
      setInfo({
        version: '2.0.0',
        build: '2025.10.25',
        total_contexts: 27,
        total_payloads: 194,
      });
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

  const content = {
    en: {
      title: 'BRS-KB Dashboard',
      subtitle: 'Platform statistics and overview',
      systemInfo: 'System Information',
      version: 'Version',
      build: 'Build',
      overview: 'Overview',
      contexts: 'XSS Contexts',
      payloads: 'Payloads',
      wafBypass: 'WAF Bypass',
      severity: 'Severity Distribution',
      contextCoverage: 'Context Coverage',
      apiStatus: 'API Status',
      online: 'Online',
      offline: 'Offline',
    },
    ru: {
      title: 'Панель управления BRS-KB',
      subtitle: 'Статистика и обзор платформы',
      systemInfo: 'Системная информация',
      version: 'Версия',
      build: 'Сборка',
      overview: 'Обзор',
      contexts: 'XSS Контексты',
      payloads: 'Payloads',
      wafBypass: 'WAF Bypass',
      severity: 'Распределение по серьезности',
      contextCoverage: 'Покрытие контекстов',
      apiStatus: 'Статус API',
      online: 'Онлайн',
      offline: 'Офлайн',
    },
  };

  const t = content[language] || content.en;

  if (loading) {
    return (
      <div className="dashboard-page">
        <div className="container">
          <div className="loading">Loading dashboard...</div>
        </div>
      </div>
    );
  }

  const totalPayloads = stats?.severity_distribution
    ? Object.values(stats.severity_distribution).reduce((a, b) => a + b, 0)
    : stats?.total_payloads || 0;

  return (
    <div className="dashboard-page">
      <div className="container">
        <div className="page-header">
          <h1>{t.title}</h1>
          <p>{t.subtitle}</p>
        </div>

        {error && (
          <div className="warning-message">
            API not available. Showing cached data.
          </div>
        )}

        <div className="dashboard-grid">
          {/* System Info Card */}
          <div className="card system-info">
            <h3>{t.systemInfo}</h3>
            <div className="info-grid">
              <div className="info-item">
                <span className="label">{t.version}</span>
                <span className="value">{info?.version}</span>
              </div>
              <div className="info-item">
                <span className="label">{t.build}</span>
                <span className="value">{info?.build}</span>
              </div>
              <div className="info-item">
                <span className="label">{t.apiStatus}</span>
                <span className={`status ${error ? 'offline' : 'online'}`}>
                  {error ? t.offline : t.online}
                </span>
              </div>
            </div>
          </div>

          {/* Stats Cards */}
          <div className="stats-row">
            <div className="stat-card">
              <div className="stat-number">{stats?.total_contexts || 27}</div>
              <div className="stat-label">{t.contexts}</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">{stats?.total_payloads || totalPayloads}</div>
              <div className="stat-label">{t.payloads}</div>
            </div>
            <div className="stat-card">
              <div className="stat-number">{stats?.waf_bypass_count || 15}</div>
              <div className="stat-label">{t.wafBypass}</div>
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="card severity-card">
            <h3>{t.severity}</h3>
            <div className="severity-bars">
              {stats?.severity_distribution && Object.entries(stats.severity_distribution).map(([severity, count]) => (
                <div key={severity} className="severity-bar-item">
                  <div className="bar-label">
                    <span className="severity-name">{severity}</span>
                    <span className="severity-count">{count}</span>
                  </div>
                  <div className="bar-container">
                    <div
                      className="bar-fill"
                      style={{
                        width: `${(count / totalPayloads) * 100}%`,
                        backgroundColor: getSeverityColor(severity),
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Context Coverage */}
          <div className="card context-card">
            <h3>{t.contextCoverage}</h3>
            <div className="context-grid">
              {stats?.context_coverage && Object.entries(stats.context_coverage)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([context, count]) => (
                  <div key={context} className="context-item">
                    <span className="context-name">{context}</span>
                    <span className="context-count">{count}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        .dashboard-page {
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

        .warning-message {
          background: #fff3cd;
          color: #856404;
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 20px;
          text-align: center;
        }

        .dashboard-grid {
          display: grid;
          gap: 20px;
        }

        .card {
          background: white;
          padding: 25px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .card h3 {
          margin-bottom: 20px;
          color: #333;
          font-size: 1.2rem;
        }

        .system-info .info-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 20px;
        }

        .info-item {
          text-align: center;
        }

        .info-item .label {
          display: block;
          color: #666;
          font-size: 13px;
          margin-bottom: 5px;
        }

        .info-item .value {
          font-size: 1.2rem;
          font-weight: 600;
          color: #333;
        }

        .status {
          padding: 4px 12px;
          border-radius: 20px;
          font-size: 14px;
          font-weight: 600;
        }

        .status.online {
          background: #e8f5e9;
          color: #2e7d32;
        }

        .status.offline {
          background: #ffebee;
          color: #c62828;
        }

        .stats-row {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 20px;
        }

        .stat-card {
          background: white;
          padding: 30px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
          text-align: center;
        }

        .stat-number {
          font-size: 3rem;
          font-weight: 700;
          color: #d32f2f;
          margin-bottom: 10px;
        }

        .stat-label {
          color: #666;
          font-size: 1rem;
          font-weight: 500;
        }

        .severity-bars {
          display: flex;
          flex-direction: column;
          gap: 15px;
        }

        .severity-bar-item {
          display: flex;
          flex-direction: column;
          gap: 5px;
        }

        .bar-label {
          display: flex;
          justify-content: space-between;
        }

        .severity-name {
          text-transform: capitalize;
          font-weight: 500;
          color: #333;
        }

        .severity-count {
          color: #666;
        }

        .bar-container {
          height: 8px;
          background: #f0f0f0;
          border-radius: 4px;
          overflow: hidden;
        }

        .bar-fill {
          height: 100%;
          border-radius: 4px;
          transition: width 0.3s;
        }

        .context-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 10px;
        }

        .context-item {
          display: flex;
          justify-content: space-between;
          padding: 10px;
          background: #f5f5f5;
          border-radius: 6px;
        }

        .context-name {
          color: #333;
          font-size: 13px;
        }

        .context-count {
          color: #d32f2f;
          font-weight: 600;
        }

        .loading {
          text-align: center;
          padding: 60px;
          color: #666;
        }

        @media (max-width: 768px) {
          .system-info .info-grid {
            grid-template-columns: 1fr;
          }

          .stats-row {
            grid-template-columns: 1fr;
          }

          .context-grid {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  );
};

export default Dashboard;
