import React from 'react';
import { Link } from 'react-router-dom';

const Home = ({ language }) => {
  const content = {
    en: {
      hero: {
        title: "Advanced XSS Intelligence Platform",
        subtitle: "Comprehensive vulnerability detection and payload testing using BRS-KB knowledge base",
        cta: "Get Started"
      },
      features: {
        title: "Key Features",
        items: [
          {
            icon: "🔍",
            title: "27 XSS Contexts",
            description: "Complete coverage of modern and legacy XSS vulnerability types"
          },
          {
            icon: "💻",
            title: "200+ Payloads",
            description: "Extensive payload database with automatic context detection"
          },
          {
            icon: "🛡️",
            title: "WAF Bypass Detection",
            description: "Advanced techniques for evading web application firewalls"
          },
          {
            icon: "🌐",
            title: "Multi-Language Support",
            description: "Full localization in English, Russian, Chinese, and Spanish"
          }
        ]
      },
      stats: {
        title: "Platform Statistics",
        items: [
          { number: "27", label: "XSS Contexts" },
          { number: "200+", label: "Payloads" },
          { number: "9", label: "CLI Commands" },
          { number: "4", label: "Languages" }
        ]
      },
      tools: {
        title: "Integrated Tools",
        items: [
          {
            name: "Burp Suite Plugin",
            description: "Professional penetration testing integration",
            link: "/plugins/burp_suite"
          },
          {
            name: "OWASP ZAP Script",
            description: "Open-source security scanning integration",
            link: "/plugins/owasp_zap"
          },
          {
            name: "Nuclei Templates",
            description: "Automated vulnerability testing templates",
            link: "/plugins/nuclei"
          },
          {
            name: "SIEM Connectors",
            description: "Enterprise monitoring system integration",
            link: "/siem_connectors"
          }
        ]
      }
    },
    ru: {
      hero: {
        title: "Расширенная Платформа XSS Разведки",
        subtitle: "Комплексное обнаружение уязвимостей и тестирование payloads с использованием базы знаний BRS-KB",
        cta: "Начать"
      },
      features: {
        title: "Ключевые Возможности",
        items: [
          {
            icon: "🔍",
            title: "27 Контекстов XSS",
            description: "Полное покрытие современных и legacy типов XSS уязвимостей"
          },
          {
            icon: "💻",
            title: "200+ Payloads",
            description: "Обширная база данных payloads с автоматическим определением контекста"
          },
          {
            icon: "🛡️",
            title: "Обнаружение Bypass WAF",
            description: "Расширенные техники обхода web application firewalls"
          },
          {
            icon: "🌐",
            title: "Мультиязычная Поддержка",
            description: "Полная локализация на английском, русском, китайском и испанском"
          }
        ]
      },
      stats: {
        title: "Статистика Платформы",
        items: [
          { number: "27", label: "Контекстов XSS" },
          { number: "200+", label: "Payloads" },
          { number: "9", label: "CLI Команд" },
          { number: "4", label: "Языка" }
        ]
      },
      tools: {
        title: "Интегрированные Инструменты",
        items: [
          {
            name: "Burp Suite Плагин",
            description: "Интеграция профессионального penetration testing",
            link: "/plugins/burp_suite"
          },
          {
            name: "OWASP ZAP Скрипт",
            description: "Интеграция open-source security scanning",
            link: "/plugins/owasp_zap"
          },
          {
            name: "Nuclei Шаблоны",
            description: "Шаблоны автоматизированного тестирования уязвимостей",
            link: "/plugins/nuclei"
          },
          {
            name: "SIEM Коннекторы",
            description: "Интеграция систем enterprise мониторинга",
            link: "/siem_connectors"
          }
        ]
      }
    },
    zh: {
      hero: {
        title: "高级 XSS 情报平台",
        subtitle: "使用 BRS-KB 知识库进行全面漏洞检测和 payload 测试",
        cta: "开始使用"
      },
      features: {
        title: "主要功能",
        items: [
          {
            icon: "🔍",
            title: "27 个 XSS 上下文",
            description: "完整覆盖现代和传统 XSS 漏洞类型"
          },
          {
            icon: "💻",
            title: "200+ 个 Payloads",
            description: "广泛的 payload 数据库与自动上下文检测"
          },
          {
            icon: "🛡️",
            title: "WAF 绕过检测",
            description: "绕过 Web 应用程序防火墙的高级技术"
          },
          {
            icon: "🌐",
            title: "多语言支持",
            description: "英语、俄语、中文和西班牙语的完整本地化"
          }
        ]
      },
      stats: {
        title: "平台统计",
        items: [
          { number: "27", label: "XSS 上下文" },
          { number: "200+", label: "Payloads" },
          { number: "9", label: "CLI 命令" },
          { number: "4", label: "语言" }
        ]
      },
      tools: {
        title: "集成工具",
        items: [
          {
            name: "Burp Suite 插件",
            description: "专业渗透测试集成",
            link: "/plugins/burp_suite"
          },
          {
            name: "OWASP ZAP 脚本",
            description: "开源安全扫描集成",
            link: "/plugins/owasp_zap"
          },
          {
            name: "Nuclei 模板",
            description: "自动化漏洞测试模板",
            link: "/plugins/nuclei"
          },
          {
            name: "SIEM 连接器",
            description: "企业监控系统集成",
            link: "/siem_connectors"
          }
        ]
      }
    },
    es: {
      hero: {
        title: "Plataforma de Inteligencia XSS Avanzada",
        subtitle: "Detección integral de vulnerabilidades y pruebas de payloads usando la base de conocimientos BRS-KB",
        cta: "Comenzar"
      },
      features: {
        title: "Características Clave",
        items: [
          {
            icon: "🔍",
            title: "27 Contextos XSS",
            description: "Cobertura completa de tipos clásicos y modernos de vulnerabilidades XSS"
          },
          {
            icon: "💻",
            title: "200+ Payloads",
            description: "Extensa base de datos de payloads con detección automática de contexto"
          },
          {
            icon: "🛡️",
            title: "Detección de Bypass WAF",
            description: "Técnicas avanzadas para evadir firewalls de aplicaciones web"
          },
          {
            icon: "🌐",
            title: "Soporte Multi-Idioma",
            description: "Localización completa en inglés, ruso, chino y español"
          }
        ]
      },
      stats: {
        title: "Estadísticas de Plataforma",
        items: [
          { number: "27", label: "Contextos XSS" },
          { number: "200+", label: "Payloads" },
          { number: "9", label: "Comandos CLI" },
          { number: "4", label: "Idiomas" }
        ]
      },
      tools: {
        title: "Herramientas Integradas",
        items: [
          {
            name: "Plugin de Burp Suite",
            description: "Integración de pruebas de penetración profesionales",
            link: "/plugins/burp_suite"
          },
          {
            name: "Script de OWASP ZAP",
            description: "Integración de escaneo de seguridad de código abierto",
            link: "/plugins/owasp_zap"
          },
          {
            name: "Plantillas Nuclei",
            description: "Plantillas de pruebas de vulnerabilidades automatizadas",
            link: "/plugins/nuclei"
          },
          {
            name: "Conectores SIEM",
            description: "Integración de sistemas de monitoreo empresarial",
            link: "/siem_connectors"
          }
        ]
      }
    }
  };

  const currentContent = content[language] || content.en;

  return (
    <div>
      {/* Hero Section */}
      <section className="hero">
        <div className="container">
          <h1>{currentContent.hero.title}</h1>
          <p>{currentContent.hero.subtitle}</p>
          <div className="hero-actions">
            <Link to="/contexts" className="btn btn-primary">
              Explore Contexts
            </Link>
            <Link to="/playground" className="btn btn-secondary">
              Try Playground
            </Link>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="features">
        <div className="container">
          <h2>{currentContent.features.title}</h2>
          <div className="features-grid">
            {currentContent.features.items.map((feature, index) => (
              <div key={index} className="feature-card">
                <div className="feature-icon">{feature.icon}</div>
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="stats-section">
        <div className="container">
          <h2>{currentContent.stats.title}</h2>
          <div className="hero-stats">
            {currentContent.stats.items.map((stat, index) => (
              <div key={index} className="stat-item">
                <div className="stat-number">{stat.number}</div>
                <div className="stat-label">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Tools Section */}
      <section className="tools-section">
        <div className="container">
          <h2>{currentContent.tools.title}</h2>
          <div className="tools-grid">
            {currentContent.tools.items.map((tool, index) => (
              <div key={index} className="tool-card">
                <h3>{tool.name}</h3>
                <p>{tool.description}</p>
                <Link to={tool.link} className="btn btn-primary">
                  Learn More
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <div className="container">
          <div className="cta-content">
            <h2>Ready to enhance your XSS security research?</h2>
            <p>Join thousands of security professionals using BRS-KB for advanced vulnerability detection and analysis.</p>
            <div className="cta-actions">
              <Link to="/playground" className="btn btn-primary">
                Start Testing
              </Link>
              <Link to="/api-docs" className="btn btn-secondary">
                View API
              </Link>
            </div>
          </div>
        </div>
      </section>

      <style jsx>{`
        .hero-actions {
          display: flex;
          gap: 20px;
          justify-content: center;
          margin-top: 40px;
        }

        .features {
          padding: 80px 0;
          background: #f8f9fa;
        }

        .features h2 {
          text-align: center;
          margin-bottom: 50px;
          font-size: 2.5rem;
          color: #333;
        }

        .features-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 30px;
        }

        .feature-card {
          text-align: center;
          padding: 30px;
          background: white;
          border-radius: 12px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .feature-icon {
          width: 60px;
          height: 60px;
          margin: 0 auto 20px;
          background: #d32f2f;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 24px;
          color: white;
        }

        .stats-section {
          padding: 60px 0;
          background: white;
        }

        .stats-section h2 {
          text-align: center;
          margin-bottom: 40px;
          font-size: 2.2rem;
          color: #333;
        }

        .hero-stats {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 30px;
          max-width: 800px;
          margin: 0 auto;
        }

        .stat-item {
          text-align: center;
          padding: 20px;
          background: #f8f9fa;
          border-radius: 8px;
        }

        .stat-number {
          font-size: 3rem;
          font-weight: 700;
          color: #d32f2f;
          margin-bottom: 10px;
        }

        .stat-label {
          font-size: 1.1rem;
          color: #666;
          font-weight: 500;
        }

        .tools-section {
          padding: 80px 0;
          background: #f8f9fa;
        }

        .tools-section h2 {
          text-align: center;
          margin-bottom: 50px;
          font-size: 2.5rem;
          color: #333;
        }

        .tools-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 30px;
        }

        .tool-card {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
          text-align: center;
        }

        .tool-card h3 {
          color: #d32f2f;
          margin-bottom: 15px;
          font-size: 1.3rem;
        }

        .tool-card p {
          color: #666;
          margin-bottom: 20px;
          line-height: 1.6;
        }

        .cta-section {
          padding: 80px 0;
          background: linear-gradient(135deg, #d32f2f 0%, #b71c1c 100%);
          color: white;
          text-align: center;
        }

        .cta-content h2 {
          font-size: 2.5rem;
          margin-bottom: 20px;
        }

        .cta-content p {
          font-size: 1.2rem;
          margin-bottom: 30px;
          opacity: 0.9;
          max-width: 600px;
          margin-left: auto;
          margin-right: auto;
        }

        .cta-actions {
          display: flex;
          gap: 20px;
          justify-content: center;
        }

        @media (max-width: 768px) {
          .hero-actions {
            flex-direction: column;
            align-items: center;
          }

          .features-grid {
            grid-template-columns: 1fr;
          }

          .hero-stats {
            grid-template-columns: repeat(2, 1fr);
          }

          .tools-grid {
            grid-template-columns: 1fr;
          }

          .cta-actions {
            flex-direction: column;
            align-items: center;
          }
        }
      `}</style>
    </div>
  );
};

export default Home;


