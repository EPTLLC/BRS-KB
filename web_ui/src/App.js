import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './styles/App.css';

// Components
import Header from './components/Header';
import Footer from './components/Footer';
import Home from './pages/Home';
import Contexts from './pages/Contexts';
import Payloads from './pages/Payloads';
import Playground from './pages/Playground';
import Dashboard from './pages/Dashboard';
import ApiDocs from './pages/ApiDocs';

function App() {
  const [currentLanguage, setCurrentLanguage] = useState('en');
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    // Check for saved preferences
    const savedLanguage = localStorage.getItem('brs-kb-language');
    const savedDarkMode = localStorage.getItem('brs-kb-dark-mode');

    if (savedLanguage) {
      setCurrentLanguage(savedLanguage);
    }
    if (savedDarkMode === 'true') {
      setDarkMode(true);
    }
  }, []);

  const changeLanguage = (lang) => {
    setCurrentLanguage(lang);
    localStorage.setItem('brs-kb-language', lang);
  };

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    localStorage.setItem('brs-kb-dark-mode', (!darkMode).toString());
  };

  return (
    <Router>
      <div className={`App ${darkMode ? 'dark' : 'light'}`}>
        <Header
          currentLanguage={currentLanguage}
          darkMode={darkMode}
          onLanguageChange={changeLanguage}
          onToggleDarkMode={toggleDarkMode}
        />

        <main className="main-content">
          <Routes>
            <Route path="/" element={<Home language={currentLanguage} />} />
            <Route path="/contexts" element={<Contexts language={currentLanguage} />} />
            <Route path="/payloads" element={<Payloads language={currentLanguage} />} />
            <Route path="/playground" element={<Playground language={currentLanguage} />} />
            <Route path="/dashboard" element={<Dashboard language={currentLanguage} />} />
            <Route path="/api-docs" element={<ApiDocs language={currentLanguage} />} />
          </Routes>
        </main>

        <Footer language={currentLanguage} />
      </div>
    </Router>
  );
}

export default App;

