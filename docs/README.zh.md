<div align="center">

# BRS-KB

### 社区 XSS 知识库

**为安全社区提供开放知识**

_面向研究人员和扫描器的高级 XSS 情报数据库_

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/brs-kb.svg)](https://pypi.org/project/brs-kb/)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-19.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-334%20passing-success.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-81%25-green.svg)]()

## 目录

- [为什么选择 BRS-KB？](#为什么选择-brs-kb)
- [安装](#安装)
- [快速开始](#快速开始)
- [可用上下文](#可用上下文)
- [功能特性](#功能特性)
- [CLI 工具](#cli-工具)
- [REST API 服务器](#rest-api-服务器)
- [Web UI](#web-ui)
- [安全扫描器插件](#安全扫描器插件)
- [SIEM 集成](#siem-集成)
- [CI/CD 流水线](#cicd-流水线)
- [使用方法](#使用方法)
- [API 参考](#api-参考)
- [示例](#示例)
- [贡献](#贡献)
- [项目结构](#项目结构)
- [测试](#测试)
- [统计信息](#统计信息)
- [故障排除](#故障排除)
- [许可证](#许可证)
- [项目信息](#项目信息)
- [相关项目](#相关项目)
- [支持政策](#支持政策)
- [致谢](#致谢)

---

社区驱动的跨站脚本攻击（XSS）漏洞综合知识库

</div>

---

## 为什么选择 BRS-KB？

| 功能 | 描述 |
|------|------|
| **27 个上下文** | 涵盖经典和现代 XSS 漏洞类型 |
| **194+ Payloads** | 按严重程度、标签和 WAF 绕过信息分类 |
| **REST API** | 内置 HTTP 服务器，用于 Web UI 和集成 |
| **零依赖** | 纯 Python 3.8+ |
| **SIEM 兼容** | CVSS 评分、CWE/OWASP 映射、严重程度级别 |
| **开源** | MIT 许可证，欢迎社区贡献 |
| **生产就绪** | 81% 测试覆盖率，SQLite 存储，模块化架构 |

## 安装

### 从 PyPI 安装（推荐）
```bash
pip install brs-kb
```

### 从源代码安装
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e .
```

**注意：** 首次运行时，系统会自动将 payloads 从内存存储迁移到 SQLite 数据库（`brs_kb/data/payloads.db`）。您也可以手动运行 `brs-kb migrate`。

### 开发者安装
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e ".[dev]"
```

**要求：** Python 3.8+ • 无外部依赖

## 快速开始

```python
from brs_kb import get_vulnerability_details, list_contexts

# 获取 XSS 上下文的详细信息
details = get_vulnerability_details('html_content')

print(details['title']) # Cross-Site Scripting (XSS) in HTML Content
print(details['severity']) # critical
print(details['cvss_score']) # 8.8
print(details['cwe']) # ['CWE-79']
print(details['owasp']) # ['A03:2021']

# 列出所有可用上下文
contexts = list_contexts()
# ['css_context', 'default', 'dom_xss', 'html_attribute', ...]
```

## 可用上下文

<details>
<summary><b>27 个 XSS 漏洞上下文</b>（点击展开）</summary>

### 核心 HTML 上下文
| 上下文 | 描述 | 行数 | 严重程度 | CVSS |
|--------|------|------|----------|------|
| `html_content` | HTML 内容中的 XSS | 407 | 严重 | 8.8 |
| `html_attribute` | HTML 属性中的 XSS | 538 | 严重 | 8.8 |
| `html_comment` | HTML 注释中的 XSS | 77 | 中等 | 5.4 |

### JavaScript 上下文
| 上下文 | 描述 | 行数 | 严重程度 | CVSS |
|--------|------|------|----------|------|
| `javascript_context` | 直接 JavaScript 注入 | 645 | 严重 | 9.0 |
| `js_string` | JavaScript 字符串注入 | 628 | 严重 | 8.8 |
| `js_object` | JavaScript 对象注入 | 628 | 高 | 7.8 |

### 样式和标记
| 上下文 | 描述 | 行数 | 严重程度 | CVSS |
|--------|------|------|----------|------|
| `css_context` | CSS 注入和样式属性 | 684 | 高 | 7.1 |
| `svg_context` | 基于 SVG 的 XSS 向量 | 297 | 高 | 7.3 |
| `markdown_context` | Markdown 渲染 XSS | 110 | 中等 | 6.1 |

### 数据格式
| 上下文 | 描述 | 行数 | 严重程度 | CVSS |
|--------|------|------|----------|------|
| `json_value` | JSON 上下文 XSS | 81 | 中等 | 6.5 |
| `xml_content` | XML/XHTML XSS 向量 | 90 | 高 | 7.1 |

### 高级向量
| 上下文 | 描述 | 行数 | 严重程度 | CVSS |
|--------|------|------|----------|------|
| `url_context` | 基于 URL/协议的 XSS | 554 | 高 | 7.5 |
| `dom_xss` | 基于 DOM 的 XSS（客户端） | 359 | 高 | 7.4 |
| `template_injection` | 客户端模板注入 | 116 | 严重 | 8.6 |
| `postmessage_xss` | PostMessage API 漏洞 | 134 | 高 | 7.4 |
| `wasm_context` | WebAssembly 上下文 XSS | 119 | 中等 | 6.8 |

### 现代 Web 技术
| 上下文 | 描述 | 行数 | 严重程度 | CVSS |
|--------|------|------|----------|------|
| `websocket_xss` | WebSocket 实时 XSS | 431 | 高 | 7.5 |
| `service_worker_xss` | Service Worker 注入 | 557 | 高 | 7.8 |
| `webrtc_xss` | WebRTC P2P 通信 XSS | 565 | 高 | 7.6 |
| `indexeddb_xss` | IndexedDB 存储 XSS | 577 | 中等 | 6.5 |
| `webgl_xss` | WebGL 着色器注入 | 611 | 中等 | 6.1 |
| `shadow_dom_xss` | Shadow DOM 封装绕过 | 539 | 高 | 7.3 |
| `custom_elements_xss` | 自定义元素 XSS | 590 | 高 | 7.1 |
| `http2_push_xss` | HTTP/2 服务器推送 XSS | 558 | 中等 | 6.8 |
| `graphql_xss` | GraphQL API 注入 | 642 | 高 | 7.4 |
| `iframe_sandbox_xss` | iframe 沙箱绕过 | 591 | 中等 | 6.3 |

### 后备
| 上下文 | 描述 | 行数 | 严重程度 | CVSS |
|--------|------|------|----------|------|
| `default` | 通用 XSS 信息 | 165 | 高 | 7.1 |

</details>

## 功能特性

### 元数据结构

每个上下文包含安全元数据：

```python
{
 # 核心信息
 "title": "Cross-Site Scripting (XSS) in HTML Content",
 "description": "详细的漏洞说明...",
 "attack_vector": "真实世界的攻击技术...",
 "remediation": "可操作的安全措施...",
 
 # 安全元数据
 "severity": "critical", # low | medium | high | critical
 "cvss_score": 8.8, # CVSS 3.1 基础评分
 "cvss_vector": "CVSS:3.1/...", # 完整 CVSS 向量字符串
 "reliability": "certain", # tentative | firm | certain
 "cwe": ["CWE-79"], # CWE 标识符
 "owasp": ["A03:2021"], # OWASP Top 10 映射
 "tags": ["xss", "html", "reflected"] # 分类标签
}
```

### 增强的反向映射系统

具有自动上下文检测和 ML-ready 功能的高级 payload 分析：

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_recommended_defenses, predict_contexts_ml_ready

# 具有置信度评分的自动上下文检测
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content'],
# 'severity': 'critical',
# 'confidence': 1.0,
# 'analysis_method': 'pattern_matching',
# 'patterns_matched': 1}

# 现代 XSS 上下文检测
websocket_info = find_contexts_for_payload('WebSocket("wss://evil.com")')
# → {'contexts': ['websocket_xss'], 'severity': 'high', 'confidence': 1.0}

# 具有特征提取的 ML-ready 分析
ml_analysis = predict_contexts_ml_ready('<script>alert(document.cookie)</script>')
# → {'contexts': ['html_content'], 'features': {'length': 39, 'has_script': True, ...}}

# 具有现代技术的增强防御映射
defenses = get_recommended_defenses('websocket_xss')
# → [{'defense': 'input_validation', 'priority': 1, 'required': True, 'tags': ['websocket']},
# {'defense': 'csp', 'priority': 1, 'required': True, 'tags': ['policy']}, ...]
```

## CLI 工具

BRS-KB 包含用于安全研究和测试的综合命令行界面：

```bash
# 安装包
pip install brs-kb

# 显示所有可用命令
brs-kb --help

# 显示系统信息
brs-kb info

# 列出所有 XSS 上下文
brs-kb list-contexts

# 获取上下文的详细信息
brs-kb get-context websocket_xss

# 分析 payload
brs-kb analyze-payload "<script>alert(1)</script>"

# 在数据库中搜索 payloads
brs-kb search-payloads websocket --limit 5

# 测试 payload 有效性
brs-kb test-payload "<script>alert(1)</script>" html_content

# 生成综合报告
brs-kb generate-report

# 验证数据库完整性
brs-kb validate

# 导出数据
brs-kb export contexts --format json --output contexts.json

# 设置语言
brs-kb language zh

# 迁移到 SQLite 数据库
brs-kb migrate

# 启动 Web UI 的 API 服务器
brs-kb serve

# 在自定义端口上启动带指标的 API 服务器
brs-kb serve --port 8080 --metrics
```

**可用命令：**
- `info` - 显示系统信息和统计信息
- `list-contexts` - 列出所有可用的 XSS 上下文及其严重程度
- `get-context <name>` - 获取详细的漏洞信息
- `analyze-payload <payload>` - 使用反向映射分析 payload
- `search-payloads <query>` - 使用相关性评分搜索 payload 数据库
- `test-payload <payload> <context>` - 在上下文中测试 payload 有效性
- `generate-report` - 生成系统综合分析
- `validate` - 验证 payload 数据库完整性
- `export <type> --format <format>` - 导出数据（payloads、contexts、reports）
- `language [lang]` - 设置或列出支持的语言（EN、RU、ZH、ES）
- `migrate [--force]` - 将 payloads 迁移到 SQLite 数据库
- `serve [--port PORT] [--host HOST] [--metrics]` - 启动 Web UI 的 REST API 服务器

## 使用方法

### 1. 安全扫描器集成

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

# 在扫描器中使用
finding = enrich_finding('dom_xss', 'https://target.com/app', 'location.hash')
```

### 2. SIEM/SOC 集成

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

### 3. Bug Bounty 报告

```python
from brs_kb import get_vulnerability_details

def generate_report(context, url, payload):
 kb = get_vulnerability_details(context)
 
 return f"""
# {kb['title']}

**严重程度**: {kb['severity'].upper()} (CVSS {kb['cvss_score']})
**CWE**: {', '.join(kb['cwe'])}

## 易受攻击的 URL
{url}

## 概念验证
```
{payload}
```

## 描述
{kb['description']}

## 修复
{kb['remediation']}
"""
```

### 4. 培训和教育

```python
from brs_kb import list_contexts, get_vulnerability_details

# 创建 XSS 学习材料
for context in list_contexts():
 details = get_vulnerability_details(context)
 
 print(f"上下文: {context}")
 print(f"严重程度: {details.get('severity', 'N/A')}")
 print(f"攻击向量: {details['attack_vector'][:200]}...")
 print("-" * 80)
```

## 安全扫描器插件

BRS-KB 包含流行安全测试工具的插件：

### Burp Suite 插件
- 代理期间实时 XSS payload 分析
- 自动检测拦截请求的上下文
- 与 27 个 XSS 上下文集成
- 专业安全团队界面

**安装：** 将 `plugins/burp_suite/BRSKBExtension.java` 复制到 Burp 扩展

### OWASP ZAP 集成
- 使用 BRS-KB 智能进行自动化 XSS 扫描
- 上下文感知的 payload 注入
- WAF 绕过技术检测
- 专业安全工作流支持

**安装：** 在 ZAP 脚本中加载 `plugins/owasp_zap/brs_kb_zap.py`

### Nuclei 模板
- 200+ 分类的 XSS payloads
- 上下文特定测试（27 个 XSS 上下文）
- WAF 绕过技术检测

**安装：** 将模板复制到 Nuclei 模板目录

## SIEM 集成

BRS-KB 与企业 SIEM 系统集成，用于实时 XSS 监控和警报。

| 平台 | 功能 | 安装 |
|------|------|------|
| **Splunk** | 仪表板、警报、趋势分析 | `siem_connectors/splunk/brs_kb_app.tar.gz` |
| **Elasticsearch** | Kibana 仪表板、ML 异常检测 | `siem_connectors/elastic/` |
| **Graylog** | GELF 集成、流处理 | `siem_connectors/graylog/` |

### 快速设置
```bash
# Splunk
cp siem_connectors/splunk/brs_kb_app.tar.gz $SPLUNK_HOME/etc/apps/

# Elasticsearch (Logstash)
cp siem_connectors/elastic/logstash.conf /etc/logstash/conf.d/

# Graylog
# 通过 Graylog UI 导入内容包
```

请参阅 [siem_connectors/README.md](siem_connectors/README.md) 了解详细配置。

## CI/CD 流水线

BRS-KB 包含用于自动化测试和部署的综合 CI/CD 配置：

### GitLab CI (`.gitlab-ci.yml`)
- 多 Python 版本测试（3.8-3.12）
- 代码质量检查和安全扫描
- 包构建和 PyPI 部署
- 性能测试和覆盖率报告

### GitLab CI (`.gitlab-ci.yml`) - 高级配置
- 跨 Python 版本的并行测试
- 包构建和部署
- 文档部署（GitLab Pages）
- 性能和安全性测试

### Jenkins 流水线 (`Jenkinsfile`)
- 具有并行执行的声明式流水线
- 工件管理和部署
- 通知集成和报告
- 企业级流水线管理

### 设置脚本 (`scripts/setup_cicd.py`)
自动化 CI/CD 流水线设置和配置。

**快速设置：**
```bash
python3 scripts/setup_cicd.py
```

请参阅 [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) 了解详细的 CI/CD 文档。

## 多语言文档

BRS-KB 包含多种语言的综合文档：

### 可用语言
- **English (EN)** - 主要文档（[README.md](../README.md)）
- **Russian (RU)** - [docs/README.ru.md](README.ru.md)
- **Chinese (ZH)** - 本文件
- **Spanish (ES)** - [docs/README.es.md](README.es.md)

### 语言切换
```bash
brs-kb language ru    # 切换到俄语
brs-kb language zh    # 切换到中文
brs-kb language es    # 切换到西班牙语
brs-kb language en    # 切换到英语
brs-kb language --list  # 列出所有支持的语言
```

### Web UI 本地化
Web UI 支持所有 4 种语言的完整本地化：
- 本地化界面元素
- 上下文特定示例
- 安全术语适配

## REST API 服务器

BRS-KB 包含内置的 REST API 服务器，用于 Web UI 集成和程序化访问：

### 启动服务器
```bash
# 启动 API 服务器（默认：http://0.0.0.0:8080）
brs-kb serve

# 自定义端口和主机
brs-kb serve --port 9000 --host 127.0.0.1

# 带 Prometheus 指标端点
brs-kb serve --metrics --metrics-port 8000
```

### API 端点

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/info` | GET | 系统信息 |
| `/api/health` | GET | 健康检查 |
| `/api/contexts` | GET | 列出所有 XSS 上下文 |
| `/api/contexts/<id>` | GET | 获取上下文详细信息 |
| `/api/payloads` | GET | 列出 payloads（带过滤器） |
| `/api/payloads/search?q=<query>` | GET | 搜索 payloads |
| `/api/analyze` | GET/POST | 分析 payload |
| `/api/defenses?context=<ctx>` | GET | 获取推荐的防御措施 |
| `/api/stats` | GET | 平台统计信息 |
| `/api/languages` | GET | 支持的语言 |
| `/api/language` | POST | 设置语言 |

### Python API
```python
from brs_kb import start_api_server, start_metrics_server

# 以编程方式启动 API 服务器
server = start_api_server(port=8080, host='0.0.0.0')

# 启动 Prometheus 指标服务器
metrics = start_metrics_server(port=8000)

# 检查是否运行
print(server.is_running())  # True

# 停止服务器
server.stop()
metrics.stop()
```

## Web UI

BRS-KB 包含基于 React 的现代 Web 界面，用于可视化探索和测试：

### Web 界面 (`web_ui/`)
**BRSKB Web UI** - 具有完整 API 集成的基于 React 的现代 Web 界面

**功能：**
- 27 个 XSS 上下文的可视化探索
- 用于 payload 分析的交互式演练场
- 实时统计仪表板
- 带搜索和过滤功能的 payloads 浏览器
- API 文档查看器
- 多语言支持（EN、RU、ZH、ES）
- 适用于所有设备的响应式设计
- API 不可用时的自动回退

**页面：**
- **Home** - 概述和快速统计
- **Contexts** - 浏览所有 XSS 漏洞上下文
- **Payloads** - 搜索和过滤 194+ payloads
- **Playground** - 交互式 payload 分析器
- **Dashboard** - 统计信息和图表
- **API Docs** - REST API 文档

**安装：**
```bash
# 终端 1：启动 API 服务器
brs-kb serve --port 8080

# 终端 2：启动 Web UI
cd web_ui
npm install
npm start
```

**配置：**
设置 `REACT_APP_API_URL` 环境变量以更改 API 端点：
```bash
REACT_APP_API_URL=http://localhost:8080/api npm start
```

请参阅 [web_ui/README.md](web_ui/README.md) 了解详细的 Web UI 文档。

## 示例

请参阅 [examples/](examples/) 目录了解集成示例：

| 示例 | 描述 |
|------|------|
| [`basic_usage.py`](examples/basic_usage.py) | 基本 API 使用和功能 |
| [`scanner_integration.py`](examples/scanner_integration.py) | 集成到安全扫描器 |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | 具有 ML-ready 功能的增强反向映射 |
| [`payload_database.py`](examples/payload_database.py) | 194+ payload 数据库和测试 API |
| [`cli_demo.py`](examples/cli_demo.py) | 命令行界面演示 |
| [`plugin_demo.py`](examples/plugin_demo.py) | 安全扫描器插件集成 |
| [`cicd_demo.py`](examples/cicd_demo.py) | CI/CD 流水线演示 |
| [`multilanguage_demo.py`](examples/multilanguage_demo.py) | 多语言支持演示 |
| [`integrated_demo.py`](examples/integrated_demo.py) | 完整系统集成展示 |

**运行示例：**
```bash
# Python 示例
python3 examples/basic_usage.py
python3 examples/scanner_integration.py
python3 examples/cli_demo.py
python3 examples/plugin_demo.py
python3 examples/integrated_demo.py

# CLI 命令
brs-kb info # 系统信息
brs-kb list-contexts # 所有 XSS 上下文
brs-kb get-context websocket_xss # 上下文详细信息
brs-kb analyze-payload "<script>alert(1)</script>" # Payload 分析
brs-kb search-payloads websocket --limit 5 # 搜索 payloads
brs-kb test-payload "<script>alert(1)</script>" html_content # 测试有效性
brs-kb generate-report # 综合报告
brs-kb validate # 数据库验证
brs-kb export contexts --format json # 导出数据

# 安全扫描器集成
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://target.com

# SIEM 集成
python3 siem_connectors/splunk/brs_kb_splunk_connector.py --api-key YOUR_KEY --splunk-url https://splunk.company.com:8088

# CI/CD 流水线
python3 scripts/setup_cicd.py

# 多语言支持
brs-kb language zh
brs-kb language --list
```

## API 参考

### 核心函数

#### `get_vulnerability_details(context: str) -> Dict[str, Any]`
获取漏洞上下文的详细信息。

```python
details = get_vulnerability_details('html_content')
```

#### `list_contexts() -> List[str]`
获取所有可用上下文的列表。

```python
contexts = list_contexts() # ['css_context', 'default', 'dom_xss', ...]
```

#### `get_kb_info() -> Dict[str, Any]`
获取知识库信息（版本、构建、上下文数量）。

```python
info = get_kb_info()
print(f"Version: {info['version']}, Total contexts: {info['total_contexts']}")
```

#### `get_kb_version() -> str`
获取版本字符串。

```python
version = get_kb_version() # "3.0.0"
```

### 增强的反向映射函数

从 `brs_kb.reverse_map` 导入：

#### `find_contexts_for_payload(payload: str) -> Dict`
具有自动上下文检测和置信度评分的高级 payload 分析。

#### `predict_contexts_ml_ready(payload: str) -> Dict`
具有特征提取的 ML-ready 分析，用于未来的机器学习集成。

#### `get_recommended_defenses(context: str) -> List[Dict]`
获取上下文的推荐防御措施，包含增强的元数据和实现详细信息。

#### `get_defense_effectiveness(defense: str) -> Dict`
获取防御机制的全面信息，包括绕过难度和标签。

#### `analyze_payload_with_patterns(payload: str) -> List[Tuple]`
针对模式数据库分析 payload，返回具有置信度评分的匹配项。

#### `get_reverse_map_info() -> Dict`
获取反向映射系统信息，包括版本、功能和统计信息。

#### `reverse_lookup(query_type: str, query: str) -> Dict`
支持 payload、上下文、防御和模式查询的通用查找函数。

### Payload 数据库函数

#### `get_payloads_by_context(context: str) -> List[Dict]`
获取在特定上下文中有效的所有 payloads。

#### `get_payloads_by_severity(severity: str) -> List[Dict]`
按严重程度级别获取所有 payloads。

#### `search_payloads(query: str) -> List[Dict]`
使用相关性评分搜索 payloads。

#### `analyze_payload_context(payload: str, context: str) -> Dict`
在特定上下文中测试 payload 有效性。

#### `get_database_info() -> Dict`
获取 payload 数据库统计信息和信息。

### CLI 工具函数

#### `get_cli() -> BRSKBCLI`
获取用于程序化使用的 CLI 实例。

**CLI 命令：**
- `brs-kb info` - 系统信息
- `brs-kb list-contexts` - 列出所有 XSS 上下文
- `brs-kb get-context <name>` - 上下文详细信息
- `brs-kb analyze-payload <payload>` - Payload 分析
- `brs-kb search-payloads <query>` - 搜索 payloads
- `brs-kb test-payload <payload> <context>` - 测试有效性
- `brs-kb generate-report` - 综合报告
- `brs-kb validate` - 数据库验证
- `brs-kb export <type>` - 导出数据

## 贡献

欢迎安全社区的贡献。

### 贡献方式

- 添加新的 XSS 上下文
- 使用新的绕过技术更新现有上下文
- 改进文档
- 报告问题或过时信息
- 分享真实世界的示例

**快速开始：**
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
git checkout -b feature/new-context
# 进行更改
pytest tests/ -v
git commit -m "Add: New context for WebSocket XSS"
git push origin feature/new-context
# 打开 Pull Request
```

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细指南。

## 项目结构

```
BRS-KB/
 brs_kb/ # 主包
 __init__.py # 具有公共导出的核心 API
 api_server.py # 用于 Web UI 的 REST API 服务器
 metrics_server.py # Prometheus 指标服务器
 schema.json # JSON Schema 验证
 reverse_map.py # 反向映射包装器（向后兼容）
 reverse_map/ # 反向映射包（模块化）
   __init__.py
   patterns.py # 上下文检测模式
   defenses.py # 防御策略
   analysis.py # Payload 分析
   utils.py # 实用函数
 i18n.py # 国际化系统
 cli.py # CLI 包装器（向后兼容）
 cli/ # CLI 包（模块化）
   __init__.py
   __main__.py # 模块执行入口点
   cli.py # 主 CLI 类
   parser.py # 参数解析器
   commands/ # 单个命令模块
     base.py # 基础命令类
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
     serve.py # API 服务器命令
 payload_testing.py # Payload 测试框架
 payloads_db.py # Payload 数据库包装器（向后兼容）
 payloads_db/ # Payload 数据库包（模块化）
   __init__.py
   data.py # 内存数据库
   models.py # 数据模型
   operations.py # CRUD 操作
   queries.py # 查询函数
   search.py # 搜索功能
   info.py # 数据库信息
   testing.py # 测试实用程序
 payloads_db_sqlite.py # SQLite 数据库实现
 migrations.py # 数据库迁移
 contexts/ # 27 个漏洞模块
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # 集成示例
 tests/ # 测试套件（pytest，334 个测试，81% 覆盖率）
 docs/ # 多语言文档
 i18n/locales/ # 翻译文件
 plugins/ # 安全扫描器插件
 siem_connectors/ # SIEM 系统集成
 web_ui/ # 基于 React 的 Web 界面
  src/
    services/api.js # 后端 API 客户端
    pages/ # 页面组件
    components/ # UI 组件
 LICENSE # MIT 许可证
 CONTRIBUTING.md # 贡献指南
 CHANGELOG.md # 版本历史
 README.md # 此文件
```

## 测试

```bash
# 运行所有测试（334 个测试）
pytest tests/ -v

# 运行覆盖率（81% 覆盖率）
pytest tests/ -v --cov=brs_kb --cov-report=term-missing

# 运行特定测试模块
pytest tests/test_basic.py -v          # 基本功能
pytest tests/test_cli.py -v            # CLI 命令
pytest tests/test_sqlite.py -v         # SQLite 数据库
pytest tests/test_api_server.py -v     # REST API 服务器
pytest tests/test_metrics_server.py -v # Prometheus 指标
```

**测试覆盖率：** 81%（334 个测试通过）

## 统计信息

| 指标 | 值 |
|------|-----|
| 总行数 | ~19,500+ |
| 上下文模块 | 27 |
| Payload 数据库 | 194+ |
| 测试覆盖率 | 81%（334 个测试） |
| CLI 命令 | 12 个命令 |
| REST API 端点 | 13 |
| 反向映射模式 | 29 |
| 安全扫描器插件 | 3 个平台 |
| SIEM 集成 | 3 个系统 |
| 多语言支持 | 4 种语言 |
| 外部依赖 | 0 |
| Python 版本 | 3.8+ |

### 功能清单

| 功能 | 状态 |
|------|------|
| REST API 服务器 | 支持 |
| Prometheus 指标 | 支持 |
| Web UI (React 18) | 支持 |
| SQLite 数据库 | 支持 |
| 多语言支持 | EN、RU、ZH、ES |
| Docker 支持 | 支持 |
| Kubernetes 支持 | 支持 |
| CI/CD 流水线 | GitHub、GitLab、Jenkins |
| ML-Ready 功能 | 支持 |
| WAF 绕过检测 | 15+ payloads |
| 现代 XSS 上下文 | WebSocket、WebRTC、GraphQL 等 |

## 故障排除

### 常见问题

| 问题 | 解决方案 |
|------|----------|
| `ModuleNotFoundError: No module named 'brs_kb'` | 从项目根目录运行 `pip install -e .` |
| SQLite 数据库未创建 | 运行 `brs-kb migrate` 或检查对 `brs_kb/data/` 的写入权限 |
| API 服务器端口已被使用 | 使用 `--port` 标志：`brs-kb serve --port 9000` |
| Web UI 无法连接到 API | 验证 API 服务器是否正在运行，检查 CORS 和 `REACT_APP_API_URL` |
| 导入时测试失败 | 确保使用 Python 3.8+ |

### 数据库问题

```bash
# 强制重新创建数据库
brs-kb migrate --force

# 检查数据库位置
python3 -c "from brs_kb.payloads_db import get_database_info; print(get_database_info())"

# 验证数据库完整性
brs-kb validate
```

### API 服务器问题

```bash
# 检查端口是否可用
lsof -i :8080

# 使用详细日志启动
brs-kb serve --port 8080 2>&1 | tee server.log

# 测试 API 健康状态
curl http://localhost:8080/api/health
```

### Web UI 问题

```bash
# 清除 npm 缓存并重新安装
cd web_ui
rm -rf node_modules package-lock.json
npm install

# 检查 API 连接
curl http://localhost:8080/api/info
```

## 许可证

**MIT 许可证** - 可在任何项目（商业或非商业）中自由使用

```
Copyright (c) 2025 EasyProTech LLC / Brabus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

请参阅 [LICENSE](LICENSE) 了解完整文本。

## 项目信息

| | |
|---|---|
| **项目** | BRS-KB (BRS XSS Knowledge Base) |
| **公司** | EasyProTech LLC |
| **网站** | [www.easypro.tech](https://www.easypro.tech) |
| **开发者** | Brabus |
| **联系方式** | [https://t.me/easyprotech](https://t.me/easyprotech) |
| **仓库** | [https://github.com/EPTLLC/BRS-KB](https://github.com/EPTLLC/BRS-KB) |
| **许可证** | MIT |
| **状态** | Production-Ready |
| **版本** | 3.0.0 |

## 相关项目

- **[BRS-XSS](https://github.com/EPTLLC/brs-xss)** - Advanced XSS Scanner（使用 BRS-KB）

## 支持政策

**不提供官方支持**

这是一个社区驱动的项目。虽然我们欢迎贡献：
- 使用 GitHub Issues 报告错误
- 使用 Pull Requests 进行贡献
- 无 SLA 或保证响应时间

此项目由社区维护。

## 致谢

- 贡献知识的安全研究人员
- 开源社区的支持
- 所有报告问题和改进的人员

---

<div align="center">

**开源 XSS 知识库**

*MIT 许可证 • Python 3.8+ • 零依赖*

</div>
