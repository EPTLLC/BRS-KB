<div align="center">

# BRS-KB

### Сообщество База Знаний XSS

**Открытые Знания для Сообщества Безопасности**

_Продвинутая База Данных XSS Интеллекта для Исследователей и Сканеров_

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/brs-kb.svg)](https://pypi.org/project/brs-kb/)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-19.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-334%20passing-success.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-81%25-green.svg)]()

## Содержание

- [Почему BRS-KB?](#почему-brs-kb)
- [Установка](#установка)
- [Быстрый Старт](#быстрый-старт)
- [Доступные Контексты](#доступные-контексты)
- [Возможности](#возможности)
- [CLI Инструмент](#cli-инструмент)
- [REST API Сервер](#rest-api-сервер)
- [Web UI](#web-ui)
- [Плагины Сканеров Безопасности](#плагины-сканеров-безопасности)
- [SIEM Интеграция](#siem-интеграция)
- [CI/CD Pipeline](#cicd-pipeline)
- [Использование](#использование)
- [API Справочник](#api-справочник)
- [Примеры](#примеры)
- [Участие](#участие)
- [Структура Проекта](#структура-проекта)
- [Тестирование](#тестирование)
- [Статистика](#статистика)
- [Устранение Неполадок](#устранение-неполадок)
- [Лицензия](#лицензия)
- [Информация о Проекте](#информация-о-проекте)
- [Связанные Проекты](#связанные-проекты)
- [Политика Поддержки](#политика-поддержки)
- [Благодарности](#благодарности)

---

Комплексная база знаний по межсайтовому выполнению скриптов (XSS) от сообщества

</div>

---

## Почему BRS-KB?

| Возможность | Описание |
|-------------|----------|
| **27 Контекстов** | Покрытие классических и современных типов XSS уязвимостей |
| **194+ Payloads** | Категоризированы с серьезностью, тегами и информацией об обходе WAF |
| **REST API** | Встроенный HTTP сервер для Web UI и интеграций |
| **Нулевые Зависимости** | Чистый Python 3.8+ |
| **SIEM Совместимость** | CVSS оценки, CWE/OWASP сопоставления, уровни серьезности |
| **Открытый Исходный Код** | MIT лицензия, приветствуются вклады сообщества |
| **Production Ready** | 81% покрытие тестами, SQLite хранилище, модульная архитектура |

## Установка

### Из PyPI (Рекомендуется)
```bash
pip install brs-kb
```

### Из Исходного Кода
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e .
```

**Примечание:** При первом запуске система автоматически мигрирует payloads из in-memory хранилища в SQLite базу данных (`brs_kb/data/payloads.db`). Также можно запустить `brs-kb migrate` вручную.

### Для Разработчиков
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e ".[dev]"
```

**Требования:** Python 3.8+ • Нет внешних зависимостей

## Быстрый Старт

```python
from brs_kb import get_vulnerability_details, list_contexts

# Получить детальную информацию о XSS контексте
details = get_vulnerability_details('html_content')

print(details['title']) # Cross-Site Scripting (XSS) in HTML Content
print(details['severity']) # critical
print(details['cvss_score']) # 8.8
print(details['cwe']) # ['CWE-79']
print(details['owasp']) # ['A03:2021']

# Получить список всех доступных контекстов
contexts = list_contexts()
# ['css_context', 'default', 'dom_xss', 'html_attribute', ...]
```

## Доступные Контексты

<details>
<summary><b>27 Контекстов Уязвимостей XSS</b> (нажмите для развертывания)</summary>

### Основные HTML Контексты
| Контекст | Описание | Строк | Серьезность | CVSS |
|----------|----------|-------|-------------|------|
| `html_content` | XSS в теле HTML | 407 | Критическая | 8.8 |
| `html_attribute` | XSS в атрибутах HTML | 538 | Критическая | 8.8 |
| `html_comment` | XSS в комментариях HTML | 77 | Средняя | 5.4 |

### JavaScript Контексты
| Контекст | Описание | Строк | Серьезность | CVSS |
|----------|----------|-------|-------------|------|
| `javascript_context` | Прямая инъекция JavaScript | 645 | Критическая | 9.0 |
| `js_string` | Инъекция строки JavaScript | 628 | Критическая | 8.8 |
| `js_object` | Инъекция объекта JavaScript | 628 | Высокая | 7.8 |

### Стиль и Разметка
| Контекст | Описание | Строк | Серьезность | CVSS |
|----------|----------|-------|-------------|------|
| `css_context` | Инъекция CSS и атрибутов стиля | 684 | Высокая | 7.1 |
| `svg_context` | SVG-based XSS векторы | 297 | Высокая | 7.3 |
| `markdown_context` | XSS при рендеринге Markdown | 110 | Средняя | 6.1 |

### Форматы Данных
| Контекст | Описание | Строк | Серьезность | CVSS |
|----------|----------|-------|-------------|------|
| `json_value` | JSON контекст XSS | 81 | Средняя | 6.5 |
| `xml_content` | XML/XHTML XSS векторы | 90 | Высокая | 7.1 |

### Расширенные Векторы
| Контекст | Описание | Строк | Серьезность | CVSS |
|----------|----------|-------|-------------|------|
| `url_context` | URL/protocol-based XSS | 554 | Высокая | 7.5 |
| `dom_xss` | DOM-based XSS (клиентская сторона) | 359 | Высокая | 7.4 |
| `template_injection` | Клиентская инъекция шаблонов | 116 | Критическая | 8.6 |
| `postmessage_xss` | PostMessage API уязвимости | 134 | Высокая | 7.4 |
| `wasm_context` | WebAssembly контекст XSS | 119 | Средняя | 6.8 |

### Современные Веб Технологии
| Контекст | Описание | Строк | Серьезность | CVSS |
|----------|----------|-------|-------------|------|
| `websocket_xss` | WebSocket реал-тайм XSS | 431 | Высокая | 7.5 |
| `service_worker_xss` | Service Worker инъекция | 557 | Высокая | 7.8 |
| `webrtc_xss` | WebRTC P2P коммуникация XSS | 565 | Высокая | 7.6 |
| `indexeddb_xss` | IndexedDB хранилище XSS | 577 | Средняя | 6.5 |
| `webgl_xss` | WebGL шейдер инъекция | 611 | Средняя | 6.1 |
| `shadow_dom_xss` | Shadow DOM инкапсуляция bypass | 539 | Высокая | 7.3 |
| `custom_elements_xss` | Custom Elements XSS | 590 | Высокая | 7.1 |
| `http2_push_xss` | HTTP/2 Server Push XSS | 558 | Средняя | 6.8 |
| `graphql_xss` | GraphQL API инъекция | 642 | Высокая | 7.4 |
| `iframe_sandbox_xss` | iframe sandbox bypass | 591 | Средняя | 6.3 |

### Резервный
| Контекст | Описание | Строк | Серьезность | CVSS |
|----------|----------|-------|-------------|------|
| `default` | Общая информация XSS | 165 | Высокая | 7.1 |

</details>

## Возможности

### Структура Метаданных

Каждый контекст включает метаданные безопасности:

```python
{
 # Основная Информация
 "title": "Cross-Site Scripting (XSS) in HTML Content",
 "description": "Детальное объяснение уязвимости...",
 "attack_vector": "Реальные техники атаки...",
 "remediation": "Практические меры безопасности...",
 
 # Метаданные Безопасности
 "severity": "critical", # low | medium | high | critical
 "cvss_score": 8.8, # CVSS 3.1 базовая оценка
 "cvss_vector": "CVSS:3.1/...", # Полная строка CVSS вектора
 "reliability": "certain", # tentative | firm | certain
 "cwe": ["CWE-79"], # Идентификаторы CWE
 "owasp": ["A03:2021"], # OWASP Top 10 сопоставление
 "tags": ["xss", "html", "reflected"] # Классификационные теги
}
```

### Улучшенная Система Обратного Отображения

Продвинутый анализ payloads с автоматическим определением контекста и ML-ready возможностями:

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_recommended_defenses, predict_contexts_ml_ready

# Автоматическое определение контекста с оценкой уверенности
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content'],
# 'severity': 'critical',
# 'confidence': 1.0,
# 'analysis_method': 'pattern_matching',
# 'patterns_matched': 1}

# Определение современных XSS контекстов
websocket_info = find_contexts_for_payload('WebSocket("wss://evil.com")')
# → {'contexts': ['websocket_xss'], 'severity': 'high', 'confidence': 1.0}

# ML-ready анализ с извлечением признаков
ml_analysis = predict_contexts_ml_ready('<script>alert(document.cookie)</script>')
# → {'contexts': ['html_content'], 'features': {'length': 39, 'has_script': True, ...}}

# Улучшенное отображение защит с современными техниками
defenses = get_recommended_defenses('websocket_xss')
# → [{'defense': 'input_validation', 'priority': 1, 'required': True, 'tags': ['websocket']},
# {'defense': 'csp', 'priority': 1, 'required': True, 'tags': ['policy']}, ...]
```

## CLI Инструмент

BRS-KB включает комплексный интерфейс командной строки для исследований безопасности и тестирования:

```bash
# Установить пакет
pip install brs-kb

# Показать все доступные команды
brs-kb --help

# Показать информацию о системе
brs-kb info

# Список всех XSS контекстов
brs-kb list-contexts

# Получить детальную информацию о контексте
brs-kb get-context websocket_xss

# Проанализировать payload
brs-kb analyze-payload "<script>alert(1)</script>"

# Поиск payloads в базе данных
brs-kb search-payloads websocket --limit 5

# Тестировать эффективность payload
brs-kb test-payload "<script>alert(1)</script>" html_content

# Сгенерировать комплексный отчет
brs-kb generate-report

# Проверить целостность базы данных
brs-kb validate

# Экспорт данных
brs-kb export contexts --format json --output contexts.json

# Установить язык
brs-kb language ru

# Мигрировать в SQLite базу данных
brs-kb migrate

# Запустить API сервер для Web UI
brs-kb serve

# Запустить API сервер на кастомном порту с метриками
brs-kb serve --port 8080 --metrics
```

**Доступные Команды:**
- `info` - Показать информацию о системе и статистику
- `list-contexts` - Список всех доступных XSS контекстов с серьезностью
- `get-context <name>` - Получить детальную информацию об уязвимости
- `analyze-payload <payload>` - Проанализировать payload с обратным отображением
- `search-payloads <query>` - Поиск базы данных payloads с релевантностью
- `test-payload <payload> <context>` - Тестировать эффективность в контексте
- `generate-report` - Сгенерировать комплексный анализ системы
- `validate` - Проверить целостность базы данных payloads
- `export <type> --format <format>` - Экспорт данных (payloads, contexts, reports)
- `language [lang]` - Установить или показать поддерживаемые языки (EN, RU, ZH, ES)
- `migrate [--force]` - Мигрировать payloads в SQLite базу данных
- `serve [--port PORT] [--host HOST] [--metrics]` - Запустить REST API сервер для Web UI

## Использование

### 1. Интеграция со Сканером Безопасности

```python
from brs_kb import get_vulnerability_details

def enrich_finding(context_type, url, payload):
 kb_data = get_vulnerability_details(context_type)
 
 return {
 'url': url,
 'payload': payload,
 'title': kb_data['title'],
 'severity': kb_data['severity'],
 'cvss_score': kb_data['cvss_score'],
 'cwe': kb_data['cwe'],
 'description': kb_data['description'],
 'remediation': kb_data['remediation']
 }

# Использование в сканере
finding = enrich_finding('dom_xss', 'https://target.com/app', 'location.hash')
```

### 2. Интеграция SIEM/SOC

```python
from brs_kb import get_vulnerability_details

def create_security_event(context, source_ip, target_url):
 kb = get_vulnerability_details(context)
 
 return {
 'event_type': 'xss_detection',
 'severity': kb['severity'],
 'cvss_score': kb['cvss_score'],
 'cvss_vector': kb['cvss_vector'],
 'cwe': kb['cwe'],
 'owasp': kb['owasp'],
 'source_ip': source_ip,
 'target': target_url,
 'requires_action': kb['severity'] in ['critical', 'high']
 }
```

### 3. Отчетность Bug Bounty

```python
from brs_kb import get_vulnerability_details

def generate_report(context, url, payload):
 kb = get_vulnerability_details(context)
 
 return f"""
# {kb['title']}

**Серьезность**: {kb['severity'].upper()} (CVSS {kb['cvss_score']})
**CWE**: {', '.join(kb['cwe'])}

## Уязвимый URL
{url}

## Доказательство Концепции
```
{payload}
```

## Описание
{kb['description']}

## Исправление
{kb['remediation']}
"""
```

### 4. Обучение и Образование

```python
from brs_kb import list_contexts, get_vulnerability_details

# Создать материалы обучения XSS
for context in list_contexts():
 details = get_vulnerability_details(context)
 
 print(f"Контекст: {context}")
 print(f"Серьезность: {details.get('severity', 'N/A')}")
 print(f"Векторы атаки: {details['attack_vector'][:200]}...")
 print("-" * 80)
```

## Плагины Сканеров Безопасности

BRS-KB включает плагины для популярных инструментов тестирования безопасности:

### Burp Suite Плагин
- Реал-тайм анализ XSS payloads во время проксирования
- Автоматическое определение контекста для перехваченных запросов
- Интеграция с 27 XSS контекстами
- Профессиональный интерфейс команды безопасности

**Установка:** Скопировать `plugins/burp_suite/BRSKBExtension.java` в расширения Burp

### OWASP ZAP Интеграция
- Автоматизированное XSS сканирование с BRS-KB intelligence
- Осознавание контекста инъекции payload
- Обнаружение техник обхода WAF
- Профессиональная поддержка рабочих процессов безопасности

**Установка:** Загрузить `plugins/owasp_zap/brs_kb_zap.py` в скрипты ZAP

### Nuclei Шаблоны
- 200+ категоризированных XSS payloads
- Контекст-специфическое тестирование (27 XSS контекстов)
- Обнаружение техник обхода WAF

**Установка:** Скопировать шаблоны в директорию шаблонов Nuclei

## SIEM Интеграция

BRS-KB интегрируется с enterprise SIEM системами для реал-тайм мониторинга XSS и алертинга.

| Платформа | Возможности | Установка |
|----------|-------------|-----------|
| **Splunk** | Дэшборды, алертинг, анализ трендов | `siem_connectors/splunk/brs_kb_app.tar.gz` |
| **Elasticsearch** | Kibana дэшборды, ML обнаружение аномалий | `siem_connectors/elastic/` |
| **Graylog** | GELF интеграция, обработка потоков | `siem_connectors/graylog/` |

### Быстрая Настройка
```bash
# Splunk
cp siem_connectors/splunk/brs_kb_app.tar.gz $SPLUNK_HOME/etc/apps/

# Elasticsearch (Logstash)
cp siem_connectors/elastic/logstash.conf /etc/logstash/conf.d/

# Graylog
# Импортировать content pack через Graylog UI
```

Смотрите [siem_connectors/README.md](siem_connectors/README.md) для детальной конфигурации.

## CI/CD Pipeline

BRS-KB включает комплексные CI/CD конфигурации для автоматизированного тестирования и развертывания:

### GitLab CI (`.gitlab-ci.yml`)
- Мульти-Python тестирование версий (3.8-3.12)
- Проверки качества кода и сканирование безопасности
- Сборка пакета и развертывание PyPI
- Тестирование производительности и покрытие отчетов

### GitLab CI (`.gitlab-ci.yml`) - Расширенная Конфигурация
- Параллельное тестирование по Python версиям
- Сборка пакета и развертывание
- Развертывание документации (GitLab Pages)
- Тестирование производительности и безопасности

### Jenkins Pipeline (`Jenkinsfile`)
- Декларативный pipeline с параллельным выполнением
- Управление артефактами и развертывание
- Интеграция уведомлений и отчетность
- Enterprise-grade управление pipeline

### Скрипт Настройки (`scripts/setup_cicd.py`)
Автоматизированная настройка CI/CD pipeline.

**Быстрая Настройка:**
```bash
python3 scripts/setup_cicd.py
```

Смотрите [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) для детальной документации CI/CD.

## Многоязычная Документация

BRS-KB включает комплексную документацию на нескольких языках:

### Доступные Языки
- **English (EN)** - Основная документация ([README.md](../README.md))
- **Russian (RU)** - Этот файл
- **Chinese (ZH)** - [docs/README.zh.md](README.zh.md)
- **Spanish (ES)** - [docs/README.es.md](README.es.md)

### Переключение Языка
```bash
brs-kb language ru    # Переключить на русский
brs-kb language zh    # Переключить на китайский
brs-kb language es    # Переключить на испанский
brs-kb language en    # Переключить на английский
brs-kb language --list  # Показать все поддерживаемые языки
```

### Локализация Web UI
Web UI поддерживает полную локализацию на всех 4 языках:
- Локализованные элементы интерфейса
- Контекст-специфические примеры
- Адаптация терминологии безопасности

## REST API Сервер

BRS-KB включает встроенный REST API сервер для интеграции Web UI и программного доступа:

### Запуск Сервера
```bash
# Запустить API сервер (по умолчанию: http://0.0.0.0:8080)
brs-kb serve

# Кастомный порт и хост
brs-kb serve --port 9000 --host 127.0.0.1

# С эндпоинтом метрик Prometheus
brs-kb serve --metrics --metrics-port 8000
```

### API Эндпоинты

| Эндпоинт | Метод | Описание |
|----------|-------|----------|
| `/api/info` | GET | Информация о системе |
| `/api/health` | GET | Проверка здоровья |
| `/api/contexts` | GET | Список всех XSS контекстов |
| `/api/contexts/<id>` | GET | Получить детали контекста |
| `/api/payloads` | GET | Список payloads (с фильтрами) |
| `/api/payloads/search?q=<query>` | GET | Поиск payloads |
| `/api/analyze` | GET/POST | Анализ payload |
| `/api/defenses?context=<ctx>` | GET | Получить рекомендуемые защиты |
| `/api/stats` | GET | Статистика платформы |
| `/api/languages` | GET | Поддерживаемые языки |
| `/api/language` | POST | Установить язык |

### Python API
```python
from brs_kb import start_api_server, start_metrics_server

# Запустить API сервер программно
server = start_api_server(port=8080, host='0.0.0.0')

# Запустить сервер метрик для Prometheus
metrics = start_metrics_server(port=8000)

# Проверить статус
print(server.is_running())  # True

# Остановить серверы
server.stop()
metrics.stop()
```

## Web UI

BRS-KB включает современный веб-интерфейс на основе React для визуального исследования и тестирования:

### Веб Интерфейс (`web_ui/`)
**BRSKB Web UI** - Современный веб-интерфейс на основе React с полной интеграцией API

**Возможности:**
- Визуальное исследование 27 XSS контекстов
- Интерактивная площадка для анализа payloads
- Дэшборд статистики в реальном времени
- Браузер payloads с поиском и фильтрацией
- Просмотр документации API
- Многоязычная поддержка (EN, RU, ZH, ES)
- Адаптивный дизайн для всех устройств
- Автоматический fallback при недоступности API

**Страницы:**
- **Home** - Обзор и быстрая статистика
- **Contexts** - Просмотр всех XSS контекстов уязвимостей
- **Payloads** - Поиск и фильтрация 194+ payloads
- **Playground** - Интерактивный анализатор payloads
- **Dashboard** - Статистика и графики
- **API Docs** - Документация REST API

**Установка:**
```bash
# Терминал 1: Запустить API сервер
brs-kb serve --port 8080

# Терминал 2: Запустить Web UI
cd web_ui
npm install
npm start
```

**Конфигурация:**
Установите переменную окружения `REACT_APP_API_URL` для изменения эндпоинта API:
```bash
REACT_APP_API_URL=http://localhost:8080/api npm start
```

Смотрите [web_ui/README.md](web_ui/README.md) для детальной документации Web UI.

## Примеры

Смотрите директорию [examples/](examples/) для примеров интеграции:

| Пример | Описание |
|--------|----------|
| [`basic_usage.py`](examples/basic_usage.py) | Базовое использование API и функциональность |
| [`scanner_integration.py`](examples/scanner_integration.py) | Интеграция в сканеры безопасности |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | Улучшенное обратное отображение с ML-ready возможностями |
| [`payload_database.py`](examples/payload_database.py) | 194+ база данных payloads с testing API |
| [`cli_demo.py`](examples/cli_demo.py) | Демонстрация интерфейса командной строки |
| [`plugin_demo.py`](examples/plugin_demo.py) | Интеграция плагинов сканеров безопасности |
| [`cicd_demo.py`](examples/cicd_demo.py) | Демонстрация CI/CD pipeline |
| [`multilanguage_demo.py`](examples/multilanguage_demo.py) | Демонстрация мультиязычной поддержки |
| [`integrated_demo.py`](examples/integrated_demo.py) | Демонстрация полной интеграции системы |

**Запуск примеров:**
```bash
# Python примеры
python3 examples/basic_usage.py
python3 examples/scanner_integration.py
python3 examples/cli_demo.py
python3 examples/plugin_demo.py
python3 examples/integrated_demo.py

# CLI команды
brs-kb info # Информация о системе
brs-kb list-contexts # Все XSS контексты
brs-kb get-context websocket_xss # Детали контекста
brs-kb analyze-payload "<script>alert(1)</script>" # Анализ payload
brs-kb search-payloads websocket --limit 5 # Поиск payloads
brs-kb test-payload "<script>alert(1)</script>" html_content # Тестировать эффективность
brs-kb generate-report # Комплексный отчет
brs-kb validate # Валидация базы данных
brs-kb export contexts --format json # Экспорт данных

# Интеграция сканеров безопасности
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://target.com

# SIEM интеграция
python3 siem_connectors/splunk/brs_kb_splunk_connector.py --api-key YOUR_KEY --splunk-url https://splunk.company.com:8088

# CI/CD pipeline
python3 scripts/setup_cicd.py

# Мультиязычная поддержка
brs-kb language ru
brs-kb language --list
```

## API Справочник

### Основные Функции

#### `get_vulnerability_details(context: str) -> Dict[str, Any]`
Получить детальную информацию об уязвимости контекста.

```python
details = get_vulnerability_details('html_content')
```

#### `list_contexts() -> List[str]`
Получить список всех доступных контекстов.

```python
contexts = list_contexts() # ['css_context', 'default', 'dom_xss', ...]
```

#### `get_kb_info() -> Dict[str, Any]`
Получить информацию о базе знаний (версия, сборка, количество контекстов).

```python
info = get_kb_info()
print(f"Version: {info['version']}, Total contexts: {info['total_contexts']}")
```

#### `get_kb_version() -> str`
Получить строку версии.

```python
version = get_kb_version() # "3.0.0"
```

### Улучшенные Функции Обратного Отображения

Импорт из `brs_kb.reverse_map`:

#### `find_contexts_for_payload(payload: str) -> Dict`
Продвинутый анализ payloads с автоматическим определением контекста и оценкой уверенности.

#### `predict_contexts_ml_ready(payload: str) -> Dict`
ML-ready анализ с извлечением признаков для будущей интеграции машинного обучения.

#### `get_recommended_defenses(context: str) -> List[Dict]`
Получить рекомендуемые защиты для контекста с улучшенными метаданными и деталями реализации.

#### `get_defense_effectiveness(defense: str) -> Dict`
Получить комплексную информацию о механизме защиты, включая сложность обхода и теги.

#### `analyze_payload_with_patterns(payload: str) -> List[Tuple]`
Анализировать payload против базы данных паттернов, возвращая совпадения с оценками уверенности.

#### `get_reverse_map_info() -> Dict`
Получить информацию о системе обратного отображения, включая версию, возможности и статистику.

#### `reverse_lookup(query_type: str, query: str) -> Dict`
Универсальная функция поиска, поддерживающая запросы payload, контекста, защиты и паттерна.

### Функции Базы Данных Payloads

#### `get_payloads_by_context(context: str) -> List[Dict]`
Получить все payloads эффективные в конкретном контексте.

#### `get_payloads_by_severity(severity: str) -> List[Dict]`
Получить все payloads по уровню серьезности.

#### `search_payloads(query: str) -> List[Dict]`
Поиск payloads с релевантностью.

#### `analyze_payload_context(payload: str, context: str) -> Dict`
Тестировать эффективность payload в конкретном контексте.

#### `get_database_info() -> Dict`
Получить статистику базы данных payloads.

### Функции CLI Инструмента

#### `get_cli() -> BRSKBCLI`
Получить экземпляр CLI для программного использования.

**CLI Команды:**
- `brs-kb info` - Информация о системе
- `brs-kb list-contexts` - Список всех XSS контекстов
- `brs-kb get-context <name>` - Детали контекста
- `brs-kb analyze-payload <payload>` - Анализ payload
- `brs-kb search-payloads <query>` - Поиск payloads
- `brs-kb test-payload <payload> <context>` - Тестировать эффективность
- `brs-kb generate-report` - Комплексный отчет
- `brs-kb validate` - Валидация базы данных
- `brs-kb export <type>` - Экспорт данных

## Участие

Вклады от сообщества безопасности приветствуются.

### Способы Участия

- Добавить новые XSS контексты
- Обновить существующие контексты с новыми обходами
- Улучшить документацию
- Сообщить о проблемах или устаревшей информации
- Поделиться реальными примерами

**Быстрый старт:**
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
git checkout -b feature/new-context
# Внести изменения
pytest tests/ -v
git commit -m "Add: New context for WebSocket XSS"
git push origin feature/new-context
# Открыть Pull Request
```

Смотрите [CONTRIBUTING.md](CONTRIBUTING.md) для детальных руководств.

## Структура Проекта

```
BRS-KB/
 brs_kb/ # Основной пакет
 __init__.py # Core API с публичными экспортами
 api_server.py # REST API сервер для Web UI
 metrics_server.py # Prometheus сервер метрик
 schema.json # JSON Schema валидация
 reverse_map.py # Reverse mapping wrapper (обратная совместимость)
 reverse_map/ # Reverse mapping package (модульный)
   __init__.py
   patterns.py # Паттерны определения контекста
   defenses.py # Стратегии защиты
   analysis.py # Анализ payloads
   utils.py # Утилиты
 i18n.py # Система интернационализации
 cli.py # CLI wrapper (обратная совместимость)
 cli/ # CLI package (модульный)
   __init__.py
   __main__.py # Точка входа для выполнения модуля
   cli.py # Основной класс CLI
   parser.py # Парсер аргументов
   commands/ # Индивидуальные модули команд
     base.py # Базовый класс команды
     list_contexts.py
     get_context.py
     analyze_payload.py
     search_payloads.py
     test_payload.py
     generate_report.py
     info.py
     validate.py
     export.py
     language.py
     migrate.py
     serve.py # Команда API сервера
 payload_testing.py # Фреймворк тестирования payloads
 payloads_db.py # Payload database wrapper (обратная совместимость)
 payloads_db/ # Payload database package (модульный)
   __init__.py
   data.py # In-memory база данных
   models.py # Модели данных
   operations.py # CRUD операции
   queries.py # Функции запросов
   search.py # Функциональность поиска
   info.py # Информация о базе данных
   testing.py # Утилиты тестирования
 payloads_db_sqlite.py # Реализация SQLite базы данных
 migrations.py # Миграции базы данных
 contexts/ # 27 модулей уязвимостей
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # Примеры интеграции
 tests/ # Тестовый набор (pytest, 334 теста, 81% покрытие)
 docs/ # Многоязычная документация
 i18n/locales/ # Файлы переводов
 plugins/ # Плагины сканеров безопасности
 siem_connectors/ # SIEM системные интеграции
 web_ui/ # React-based веб интерфейс
  src/
    services/api.js # API клиент для бэкенда
    pages/ # Компоненты страниц
    components/ # UI компоненты
 LICENSE # MIT License
 CONTRIBUTING.md # Руководство по вкладам
 CHANGELOG.md # История версий
 README.md # Этот файл
```

## Тестирование

```bash
# Запустить все тесты (334 теста)
pytest tests/ -v

# Запустить с покрытием (81% покрытие)
pytest tests/ -v --cov=brs_kb --cov-report=term-missing

# Запустить конкретные тестовые модули
pytest tests/test_basic.py -v          # Базовая функциональность
pytest tests/test_cli.py -v            # CLI команды
pytest tests/test_sqlite.py -v         # SQLite база данных
pytest tests/test_api_server.py -v     # REST API сервер
pytest tests/test_metrics_server.py -v # Prometheus метрики
```

**Покрытие Тестов:** 81% (334 теста проходят)

## Статистика

| Метрика | Значение |
|---------|----------|
| Общее Строк | ~19,500+ |
| Модули Контекста | 27 |
| База Данных Payloads | 194+ |
| Покрытие Тестов | 81% (334 теста) |
| CLI Команды | 12 команд |
| REST API Эндпоинты | 13 |
| Шаблоны Обратного Отображения | 29 |
| Плагины Сканеров | 3 платформы |
| SIEM Интеграции | 3 системы |
| Многоязычная Поддержка | 4 языка |
| Внешние Зависимости | 0 |
| Python Версия | 3.8+ |

### Чеклист Возможностей

| Возможность | Статус |
|-------------|--------|
| REST API Сервер | Поддерживается |
| Prometheus Метрики | Поддерживается |
| Web UI (React 18) | Поддерживается |
| SQLite База Данных | Поддерживается |
| Многоязычная Поддержка | EN, RU, ZH, ES |
| Docker Поддержка | Поддерживается |
| Kubernetes Поддержка | Поддерживается |
| CI/CD Pipelines | GitHub, GitLab, Jenkins |
| ML-Ready Возможности | Поддерживается |
| WAF Bypass Обнаружение | 15+ payloads |
| Современные XSS Контексты | WebSocket, WebRTC, GraphQL и др. |

## Устранение Неполадок

### Частые Проблемы

| Проблема | Решение |
|----------|---------|
| `ModuleNotFoundError: No module named 'brs_kb'` | Запустить `pip install -e .` из корня проекта |
| SQLite база данных не создана | Запустить `brs-kb migrate` или проверить права записи в `brs_kb/data/` |
| Порт API сервера уже используется | Использовать флаг `--port`: `brs-kb serve --port 9000` |
| Web UI не может подключиться к API | Проверить запущен ли API сервер, проверить CORS и `REACT_APP_API_URL` |
| Тесты падают при импорте | Убедиться что используется Python 3.8+ |

### Проблемы с Базой Данных

```bash
# Принудительное пересоздание базы данных
brs-kb migrate --force

# Проверить расположение базы данных
python3 -c "from brs_kb.payloads_db import get_database_info; print(get_database_info())"

# Проверить целостность базы данных
brs-kb validate
```

### Проблемы с API Сервером

```bash
# Проверить доступность порта
lsof -i :8080

# Запустить с подробным логированием
brs-kb serve --port 8080 2>&1 | tee server.log

# Проверить здоровье API
curl http://localhost:8080/api/health
```

### Проблемы с Web UI

```bash
# Очистить npm кэш и переустановить
cd web_ui
rm -rf node_modules package-lock.json
npm install

# Проверить подключение к API
curl http://localhost:8080/api/info
```

## Лицензия

**MIT License** - Свободно для использования в любом проекте (коммерческом или некоммерческом)

```
Copyright (c) 2025 EasyProTech LLC / Brabus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

Смотрите [LICENSE](LICENSE) для полного текста.

## Информация о Проекте

| | |
|---|---|
| **Проект** | BRS-KB (BRS XSS Knowledge Base) |
| **Компания** | EasyProTech LLC |
| **Вебсайт** | [www.easypro.tech](https://www.easypro.tech) |
| **Разработчик** | Brabus |
| **Контакт** | [https://t.me/easyprotech](https://t.me/easyprotech) |
| **Репозиторий** | [https://github.com/EPTLLC/BRS-KB](https://github.com/EPTLLC/BRS-KB) |
| **Лицензия** | MIT |
| **Статус** | Production-Ready |
| **Версия** | 3.0.0 |

## Связанные Проекты

- **[BRS-XSS](https://github.com/EPTLLC/brs-xss)** - Advanced XSS Scanner (использует BRS-KB)

## Политика Поддержки

**ОФИЦИАЛЬНАЯ ПОДДЕРЖКА НЕ ПРЕДОСТАВЛЯЕТСЯ**

Это проект, управляемый сообществом. Пока мы приветствуем вклады:
- Используйте GitHub Issues для отчетов об ошибках
- Используйте Pull Requests для вклада
- Нет SLA или гарантированного времени ответа

Этот проект поддерживается сообществом.

## Благодарности

- Исследователям безопасности, которые вносят знания
- Open-source сообществу за поддержку
- Всем, кто сообщает о проблемах и улучшениях

---

<div align="center">

**Открытая База Знаний XSS**

*MIT License • Python 3.8+ • Нулевые Зависимости*

</div>
