# BRS-KB

### Сообщество База Знаний XSS

**Открытые Знания для Сообщества Безопасности**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-16.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-passing-success.svg)]()

Комплексная база знаний по межсайтовому выполнению скриптов (XSS) от сообщества

[Возможности](#-возможности) • [Установка](#-установка) • [Использование](#-использование) • [API](#-справочник-api) • [Примеры](#-примеры) • [Участие](#-участие)

---

## Почему BRS-KB?

| Возможность | Описание |
|-------------|----------|
| **27 Контекстов** | Покрытие классических и современных типов XSS уязвимостей |
| **Детальная Информация** | Векторы атак, техники обхода, стратегии защиты |
| **Простой API** | Python библиотека, легкая интеграция |
| **Нулевые Зависимости** | Чистый Python 3.8+ |
| **SIEM Совместимость** | CVSS оценки, CWE/OWASP сопоставления, уровни серьезности |
| **Открытый Исходный Код** | MIT лицензия, приветствуются вклады сообщества |
| **В Продакшене** | Используется в сканерах безопасности и инструментах |

## Установка

```bash
pip install brs-kb
```

**Из исходного кода:**
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e .
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
| Контекст | Описание | Строк | Серьезность |
|----------|----------|-------|-------------|
| `html_content` | XSS в теле HTML | 398 | Критическая |
| `html_attribute` | XSS в атрибутах HTML | 529 | Критическая |
| `html_comment` | XSS в комментариях HTML | 68 | Средняя |

### JavaScript Контексты
| Контекст | Описание | Строк | Серьезность |
|----------|----------|-------|-------------|
| `javascript_context` | Прямая инъекция JavaScript | 636 | Критическая |
| `js_string` | Инъекция строки JavaScript | 619 | Критическая |
| `js_object` | Инъекция объекта JavaScript | 619 | Высокая |

### Стиль и Разметка
| Контекст | Описание | Строк | Серьезность |
|----------|----------|-------|-------------|
| `css_context` | Инъекция CSS и атрибутов стиля | 675 | Высокая |
| `svg_context` | SVG-based XSS векторы | 288 | Высокая |
| `markdown_context` | XSS при рендеринге Markdown | 101 | Средняя |

### Форматы Данных
| Контекст | Описание | Строк | Серьезность |
|----------|----------|-------|-------------|
| `json_value` | JSON контекст XSS | 72 | Средняя |
| `xml_content` | XML/XHTML XSS векторы | 81 | Высокая |

### Расширенные Векторы
| Контекст | Описание | Строк | Серьезность |
|----------|----------|-------|-------------|
| `url_context` | URL/protocol-based XSS | 545 | Высокая |
| `dom_xss` | DOM-based XSS (клиентская сторона) | 350 | Высокая |
| `template_injection` | Клиентская инъекция шаблонов | 107 | Критическая |
| `postmessage_xss` | PostMessage API уязвимости | 125 | Высокая |
| `wasm_context` | WebAssembly контекст XSS | 110 | Средняя |

### Современные Веб Технологии (НОВОЕ)
| Контекст | Описание | Строк | Серьезность |
|----------|----------|-------|-------------|
| `websocket_xss` | WebSocket реал-тайм XSS | 407 | Высокая |
| `service_worker_xss` | Service Worker инъекция | 398 | Высокая |
| `webrtc_xss` | WebRTC P2P коммуникация XSS | 420 | Высокая |
| `indexeddb_xss` | IndexedDB хранилище XSS | 378 | Средняя |
| `webgl_xss` | WebGL шейдер инъекция | 395 | Средняя |
| `shadow_dom_xss` | Shadow DOM инкапсуляция bypass | 385 | Высокая |
| `custom_elements_xss` | Custom Elements XSS | 390 | Высокая |
| `http2_push_xss` | HTTP/2 Server Push XSS | 375 | Средняя |
| `graphql_xss` | GraphQL API инъекция | 390 | Высокая |
| `iframe_sandbox_xss` | iframe sandbox bypass | 380 | Средняя |

### Резервный
| Контекст | Описание | Строк | Серьезность |
|----------|----------|-------|-------------|
| `default` | Общая информация XSS | 156 | - |

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

### Система Обратного Отображения

Отображение payloads в контексты и защиты:

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_defenses_for_context

# Отображение Payload → Context
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content', 'html_comment', 'svg_context'],
# 'severity': 'critical',
# 'defenses': ['html_encoding', 'csp', 'sanitization']}

# Отображение Context → Defense
defenses = get_defenses_for_context('html_content')
# → [{'defense': 'html_encoding', 'priority': 1, 'required': True},
# {'defense': 'csp', 'priority': 1, 'required': True}, ...]
```

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
- Тестирование современных веб технологий

**Установка:** Скопировать шаблоны в директорию шаблонов Nuclei

Смотрите [plugins/README.md](plugins/README.md) для детальных инструкций установки и использования.

## SIEM Интеграция

BRS-KB интегрируется с enterprise SIEM системами для реал-тайм мониторинга:

#### Splunk Интеграция
- Реал-тайм ingest XSS уязвимости данных
- Кастомные дэшборды для анализа XSS контекстов
- Правила алертинга для критических уязвимостей
- Исторический анализ трендов

**Установка:** Скопировать `siem_connectors/splunk/brs_kb_app.tar.gz` в apps директорию Splunk

#### Elasticsearch Интеграция
- Logstash/Beats интеграция для BRS-KB данных
- Kibana дэшборды для XSS анализа
- Машинное обучение обнаружение аномалий
- Elasticsearch Watcher алертинг

**Установка:** Развернуть конфигурацию Logstash из `siem_connectors/elastic/`

#### Graylog Интеграция
- GELF интеграция для реал-тайм ingest логов
- Кастомные дэшборды и виджеты
- Правила алертинга и уведомлений
- Обработка потоков для XSS событий

**Установка:** Импортировать content pack из `siem_connectors/graylog/`

Смотрите [siem_connectors/README.md](siem_connectors/README.md) для детальных инструкций установки и использования.

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

## Примеры

Смотрите директорию [examples/](examples/) для примеров интеграции:

| Пример | Описание |
|--------|----------|
| [`basic_usage.py`](examples/basic_usage.py) | Базовое использование API и функциональность |
| [`scanner_integration.py`](examples/scanner_integration.py) | Интеграция в сканеры безопасности |
| [`siem_integration.py`](examples/siem_integration.py) | SIEM/SOC threat intelligence |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | Улучшенное обратное отображение с ML-ready возможностями |
| [`payload_database.py`](examples/payload_database.py) | 200+ база данных payloads с testing API |
| [`cli_demo.py`](examples/cli_demo.py) | Демонстрация интерфейса командной строки |
| [`plugin_demo.py`](examples/plugin_demo.py) | Интеграция плагинов сканеров безопасности |
| [`siem_integration.py`](examples/siem_integration.py) | Демонстрация интеграции SIEM систем |
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
brs-kb analyze-payload "<script>alert(1)</script>" # Анализ payload
brs-kb search-payloads websocket # Поиск payloads
brs-kb generate-report # Комплексный отчет

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
version = get_kb_version() # "2.0.0"
```

### Функции Обратного Отображения

Импорт из `brs_kb.reverse_map`:

#### `find_contexts_for_payload(payload: str) -> Dict`
Найти контексты, где payload эффективен.

#### `get_defenses_for_context(context: str) -> List[Dict]`
Получить рекомендуемые защиты для контекста.

#### `get_defense_info(defense: str) -> Dict`
Получить детали реализации механизма защиты.

### Функции Базы Данных Payloads

#### `get_payloads_by_context(context: str) -> List[Dict]`
Получить все payloads эффективные в конкретном контексте.

#### `get_payloads_by_severity(severity: str) -> List[Dict]`
Получить все payloads по уровню серьезности.

#### `search_payloads(query: str) -> List[Dict]`
Поиск payloads с релевантностью.

#### `test_payload_in_context(payload: str, context: str) -> Dict`
Тестировать эффективность payload в контексте.

#### `get_database_info() -> Dict`
Получить статистику базы данных payloads.

### CLI Функции

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
 __init__.py # Core API
 schema.json # JSON Schema валидация
 reverse_map.py # Система обратного отображения
 i18n.py # Система интернационализации
 cli.py # Интерфейс командной строки
 payload_testing.py # Фреймворк тестирования payloads
 payloads_db.py # База данных payloads
 contexts/ # 27 модулей уязвимостей
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # Примеры интеграции
 tests/ # Тестовый набор (pytest)
 docs/ # Многоязычная документация
 i18n/locales/ # Файлы переводов
 plugins/ # Плагины сканеров безопасности
 siem_connectors/ # SIEM системные интеграции
 web_ui/ # React-based веб интерфейс
 LICENSE # MIT License
 CONTRIBUTING.md # Руководство по вкладам
 CHANGELOG.md # История версий
 README.md # Этот файл
```

## Тестирование

```bash
# Запустить все тесты
pytest tests/ -v

# Запустить с покрытием (требует pytest-cov)
pytest tests/ -v --cov=brs_kb

# Запустить конкретный тест
pytest tests/test_basic.py -v
```

## Статистика

| Метрика | Значение |
|---------|----------|
| Общее Строк | ~16,500+ |
| Модули Контекста | 27 |
| База Данных Payloads | 200+ |
| Шаблоны Обратного Отображения | 29 |
| Поддерживаемые Контексты | 27 |
| Средний Размер Модуля | 418 строк |
| Покрытие Тестов | 33 теста |
| CLI Команды | 9 команд |
| Плагины Сканеров | 3 платформы |
| SIEM Интеграции | 3 системы |
| CI/CD Pipelines | GitLab CI, Jenkins |
| Языки | 4 языковая поддержка |
| Внешние Зависимости | 0 |
| Python Версия | 3.8+ |
| Качество Кода | Production-ready |
| ML Ready | |
| Confidence Scoring | |
| Modern XSS Support | |
| WebSocket XSS | |
| Service Worker XSS | |
| WebRTC XSS | |
| GraphQL XSS | |
| Shadow DOM XSS | |
| Custom Elements XSS | |
| Payload Testing API | |
| WAF Bypass Detection | |
| CLI Tool | |
| Export Capabilities | |
| Security Scanner Plugins | |
| Burp Suite Integration | |
| OWASP ZAP Integration | |
| Nuclei Templates | |
| SIEM Connectors | |
| Splunk Integration | |
| Elasticsearch Integration | |
| Graylog Integration | |
| CI/CD Automation | |
| GitLab CI | |
| Jenkins Pipeline | |
| Multi-Language Support | |
| Russian Localization | |
| Chinese Localization | |
| Spanish Localization | |

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
| **Версия** | 2.0.0 |

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

[Звезда на GitHub](https://github.com/EPTLLC/BRS-KB) • [Сообщить об Ошибке](https://github.com/EPTLLC/BRS-KB/issues) • [Запросить Возможность](https://github.com/EPTLLC/BRS-KB/issues)

</div>
