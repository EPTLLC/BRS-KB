import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const Header = ({ currentLanguage, darkMode, onLanguageChange, onToggleDarkMode }) => {
  const location = useLocation();

  const navigation = [
    { path: '/', label: 'Home' },
    { path: '/contexts', label: 'Contexts' },
    { path: '/payloads', label: 'Payloads' },
    { path: '/playground', label: 'Playground' },
    { path: '/dashboard', label: 'Dashboard' },
    { path: '/api-docs', label: 'API Docs' }
  ];

  const languages = [
    { code: 'en', label: 'English' },
    { code: 'ru', label: 'Русский' },
    { code: 'zh', label: '中文' },
    { code: 'es', label: 'Español' }
  ];

  return (
    <header className="navbar">
      <div className="container">
        <div className="navbar-content">
          <Link to="/" className="logo">
            <span className="logo-text">BRS-KB</span>
            <span className="logo-subtitle">XSS Knowledge Base</span>
          </Link>

          <nav className="nav-links">
            {navigation.map(item => (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
              >
                {item.label}
              </Link>
            ))}
          </nav>

          <div className="nav-controls">
            <select
              value={currentLanguage}
              onChange={(e) => onLanguageChange(e.target.value)}
              className="language-selector"
            >
              {languages.map(lang => (
                <option key={lang.code} value={lang.code}>
                  {lang.label}
                </option>
              ))}
            </select>

            <button
              onClick={onToggleDarkMode}
              className="theme-toggle"
              title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? '☀️' : '🌙'}
            </button>
          </div>
        </div>
      </div>

      <style jsx>{`
        .navbar {
          background: white;
          padding: 15px 0;
          border-bottom: 1px solid #eee;
          position: sticky;
          top: 0;
          z-index: 100;
        }

        .navbar-content {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .logo {
          text-decoration: none;
          display: flex;
          flex-direction: column;
          align-items: flex-start;
        }

        .logo-text {
          font-size: 1.5rem;
          font-weight: 700;
          color: #d32f2f;
        }

        .logo-subtitle {
          font-size: 0.8rem;
          color: #666;
          font-weight: 400;
        }

        .nav-links {
          display: flex;
          list-style: none;
          gap: 30px;
          margin: 0;
          padding: 0;
        }

        .nav-link {
          text-decoration: none;
          color: #333;
          font-weight: 500;
          padding: 10px 15px;
          border-radius: 4px;
          transition: all 0.3s ease;
        }

        .nav-link:hover,
        .nav-link.active {
          color: #d32f2f;
          background-color: #fef7f7;
        }

        .nav-controls {
          display: flex;
          gap: 15px;
          align-items: center;
        }

        .language-selector {
          padding: 8px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
          background: white;
          font-size: 14px;
          cursor: pointer;
        }

        .language-selector:focus {
          outline: none;
          border-color: #d32f2f;
        }

        .theme-toggle {
          background: none;
          border: 1px solid #ddd;
          border-radius: 4px;
          padding: 8px 12px;
          cursor: pointer;
          font-size: 16px;
          transition: all 0.3s ease;
        }

        .theme-toggle:hover {
          background-color: #f5f5f5;
        }

        @media (max-width: 768px) {
          .navbar-content {
            flex-direction: column;
            gap: 15px;
          }

          .nav-links {
            gap: 15px;
            flex-wrap: wrap;
            justify-content: center;
          }

          .nav-controls {
            order: -1;
          }
        }
      `}</style>
    </header>
  );
};

export default Header;

