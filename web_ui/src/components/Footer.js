import React from 'react';

const Footer = ({ language }) => {
  const currentYear = new Date().getFullYear();

  const footerContent = {
    en: {
      description: 'Advanced XSS Intelligence Database for Researchers and Scanners',
      sections: {
        product: 'Product',
        community: 'Community',
        support: 'Support',
        company: 'Company'
      },
      links: {
        product: [
          'Documentation',
          'API Reference',
          'Examples',
          'CLI Tool'
        ],
        community: [
          'GitHub',
          'Issues',
          'Discussions',
          'Contributing'
        ],
        support: [
          'Help Center',
          'Bug Reports',
          'Feature Requests',
          'Contact'
        ],
        company: [
          'About',
          'Blog',
          'Careers',
          'Privacy Policy'
        ]
      }
    },
    ru: {
      description: 'Расширенная база данных XSS разведки для исследователей и сканеров',
      sections: {
        product: 'Продукт',
        community: 'Сообщество',
        support: 'Поддержка',
        company: 'Компания'
      },
      links: {
        product: [
          'Документация',
          'API Справочник',
          'Примеры',
          'CLI Инструмент'
        ],
        community: [
          'GitHub',
          'Проблемы',
          'Обсуждения',
          'Вклад'
        ],
        support: [
          'Центр Помощи',
          'Отчеты об Ошибках',
          'Запросы Функций',
          'Контакт'
        ],
        company: [
          'О Нас',
          'Блог',
          'Карьера',
          'Политика Конфиденциальности'
        ]
      }
    },
    zh: {
      description: '高级XSS情报数据库，用于研究人员和扫描器',
      sections: {
        product: '产品',
        community: '社区',
        support: '支持',
        company: '公司'
      },
      links: {
        product: [
          '文档',
          'API 参考',
          '示例',
          'CLI 工具'
        ],
        community: [
          'GitHub',
          '问题',
          '讨论',
          '贡献'
        ],
        support: [
          '帮助中心',
          '错误报告',
          '功能请求',
          '联系'
        ],
        company: [
          '关于',
          '博客',
          '职业',
          '隐私政策'
        ]
      }
    },
    es: {
      description: 'Base de datos avanzada de inteligencia XSS para investigadores y escáneres',
      sections: {
        product: 'Producto',
        community: 'Comunidad',
        support: 'Soporte',
        company: 'Empresa'
      },
      links: {
        product: [
          'Documentación',
          'Referencia API',
          'Ejemplos',
          'Herramienta CLI'
        ],
        community: [
          'GitHub',
          'Problemas',
          'Discusiones',
          'Contribuir'
        ],
        support: [
          'Centro de Ayuda',
          'Reportes de Errores',
          'Solicitudes de Funciones',
          'Contacto'
        ],
        company: [
          'Acerca de',
          'Blog',
          'Carreras',
          'Política de Privacidad'
        ]
      }
    }
  };

  const content = footerContent[language] || footerContent.en;

  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-section">
            <h4>BRS-KB</h4>
            <p>{content.description}</p>
            <div className="social-links">
              <a href="https://github.com/EPTLLC/BRS-KB" target="_blank" rel="noopener noreferrer">
                GitHub
              </a>
              <a href="https://t.me/easyprotech" target="_blank" rel="noopener noreferrer">
                Telegram
              </a>
            </div>
          </div>

          <div className="footer-section">
            <h4>{content.sections.product}</h4>
            <ul>
              {content.links.product.map((link, index) => (
                <li key={index}>
                  <a href="#">{link}</a>
                </li>
              ))}
            </ul>
          </div>

          <div className="footer-section">
            <h4>{content.sections.community}</h4>
            <ul>
              {content.links.community.map((link, index) => (
                <li key={index}>
                  <a href="#">{link}</a>
                </li>
              ))}
            </ul>
          </div>

          <div className="footer-section">
            <h4>{content.sections.support}</h4>
            <ul>
              {content.links.support.map((link, index) => (
                <li key={index}>
                  <a href="#">{link}</a>
                </li>
              ))}
            </ul>
          </div>

          <div className="footer-section">
            <h4>{content.sections.company}</h4>
            <ul>
              {content.links.company.map((link, index) => (
                <li key={index}>
                  <a href="#">{link}</a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="footer-bottom">
          <p>
            © {currentYear} EasyProTech LLC. All rights reserved. |
            Licensed under MIT License |
            Version 1.1.0 |
            Built with ❤️ for the security community
          </p>
        </div>
      </div>

      <style jsx>{`
        .footer {
          background: #333;
          color: white;
          padding: 30px 0;
          margin-top: 50px;
        }

        .footer-content {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 30px;
        }

        .footer-section h4 {
          color: #d32f2f;
          margin-bottom: 15px;
          font-size: 1.1rem;
        }

        .footer-section p {
          color: #ccc;
          margin-bottom: 15px;
          line-height: 1.6;
        }

        .footer-section ul {
          list-style: none;
          padding: 0;
        }

        .footer-section li {
          margin-bottom: 8px;
        }

        .footer-section a {
          color: #ccc;
          text-decoration: none;
          transition: color 0.3s ease;
        }

        .footer-section a:hover {
          color: #d32f2f;
        }

        .social-links {
          display: flex;
          gap: 15px;
        }

        .social-links a {
          background: #555;
          padding: 8px 12px;
          border-radius: 4px;
          transition: background-color 0.3s ease;
        }

        .social-links a:hover {
          background: #d32f2f;
        }

        .footer-bottom {
          border-top: 1px solid #555;
          margin-top: 30px;
          padding-top: 20px;
          text-align: center;
          color: #999;
          font-size: 0.9rem;
        }

        @media (max-width: 768px) {
          .footer-content {
            grid-template-columns: 1fr;
            gap: 20px;
          }

          .social-links {
            justify-content: center;
          }
        }
      `}</style>
    </footer>
  );
};

export default Footer;


