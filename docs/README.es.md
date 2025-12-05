<div align="center">

# BRS-KB

### Base de Conocimientos XSS de la Comunidad

**Conocimiento Abierto para la Comunidad de Seguridad**

_Base de Datos Avanzada de Inteligencia XSS para Investigadores y Escáneres_

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/brs-kb.svg)](https://pypi.org/project/brs-kb/)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-19.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-334%20passing-success.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-81%25-green.svg)]()

## Tabla de Contenidos

- [¿Por qué BRS-KB?](#por-qué-brs-kb)
- [Instalación](#instalación)
- [Inicio Rápido](#inicio-rápido)
- [Contextos Disponibles](#contextos-disponibles)
- [Características](#características)
- [Herramienta CLI](#herramienta-cli)
- [Servidor REST API](#servidor-rest-api)
- [Web UI](#web-ui)
- [Plugins de Escáneres de Seguridad](#plugins-de-escáneres-de-seguridad)
- [Integración SIEM](#integración-siem)
- [Pipeline CI/CD](#pipeline-cicd)
- [Uso](#uso)
- [Referencia API](#referencia-api)
- [Ejemplos](#ejemplos)
- [Contribución](#contribución)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Pruebas](#pruebas)
- [Estadísticas](#estadísticas)
- [Solución de Problemas](#solución-de-problemas)
- [Licencia](#licencia)
- [Información del Proyecto](#información-del-proyecto)
- [Proyectos Relacionados](#proyectos-relacionados)
- [Política de Soporte](#política-de-soporte)
- [Reconocimientos](#reconocimientos)

---

Base de conocimientos integral y comunitaria para vulnerabilidades de Cross-Site Scripting (XSS)

</div>

---

## ¿Por qué BRS-KB?

| Característica | Descripción |
|---------------|-------------|
| **27 Contextos** | Cobertura de tipos clásicos y modernos de vulnerabilidades XSS |
| **194+ Payloads** | Categorizados con severidad, etiquetas e información de bypass WAF |
| **REST API** | Servidor HTTP integrado para Web UI e integraciones |
| **Cero Dependencias** | Python puro 3.8+ |
| **Compatible con SIEM** | Puntuaciones CVSS, mapeos CWE/OWASP, niveles de severidad |
| **Código Abierto** | Licencia MIT, contribuciones comunitarias bienvenidas |
| **Production Ready** | 81% cobertura de pruebas, almacenamiento SQLite, arquitectura modular |

## Instalación

### Desde PyPI (Recomendado)
```bash
pip install brs-kb
```

### Desde el Código Fuente
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e .
```

**Nota:** En la primera ejecución, el sistema migrará automáticamente los payloads del almacenamiento en memoria a la base de datos SQLite (`brs_kb/data/payloads.db`). También puede ejecutar `brs-kb migrate` manualmente.

### Para Desarrolladores
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e ".[dev]"
```

**Requisitos:** Python 3.8+ • Sin dependencias externas

## Inicio Rápido

```python
from brs_kb import get_vulnerability_details, list_contexts

# Obtener información detallada sobre contexto XSS
details = get_vulnerability_details('html_content')

print(details['title']) # Cross-Site Scripting (XSS) in HTML Content
print(details['severity']) # critical
print(details['cvss_score']) # 8.8
print(details['cwe']) # ['CWE-79']
print(details['owasp']) # ['A03:2021']

# Listar todos los contextos disponibles
contexts = list_contexts()
# ['css_context', 'default', 'dom_xss', 'html_attribute', ...]
```

## Contextos Disponibles

<details>
<summary><b>27 Contextos de Vulnerabilidades XSS</b> (haga clic para expandir)</summary>

### Contextos HTML Principales
| Contexto | Descripción | Líneas | Severidad | CVSS |
|----------|-------------|--------|-----------|------|
| `html_content` | XSS en contenido HTML | 407 | Crítica | 8.8 |
| `html_attribute` | XSS en atributos HTML | 538 | Crítica | 8.8 |
| `html_comment` | XSS en comentarios HTML | 77 | Media | 5.4 |

### Contextos JavaScript
| Contexto | Descripción | Líneas | Severidad | CVSS |
|----------|-------------|--------|-----------|------|
| `javascript_context` | Inyección directa de JavaScript | 645 | Crítica | 9.0 |
| `js_string` | Inyección de cadena JavaScript | 628 | Crítica | 8.8 |
| `js_object` | Inyección de objeto JavaScript | 628 | Alta | 7.8 |

### Estilo y Marcado
| Contexto | Descripción | Líneas | Severidad | CVSS |
|----------|-------------|--------|-----------|------|
| `css_context` | Inyección CSS y atributos de estilo | 684 | Alta | 7.1 |
| `svg_context` | Vectores XSS basados en SVG | 297 | Alta | 7.3 |
| `markdown_context` | XSS en renderizado Markdown | 110 | Media | 6.1 |

### Formatos de Datos
| Contexto | Descripción | Líneas | Severidad | CVSS |
|----------|-------------|--------|-----------|------|
| `json_value` | XSS en contexto JSON | 81 | Media | 6.5 |
| `xml_content` | Vectores XSS XML/XHTML | 90 | Alta | 7.1 |

### Vectores Avanzados
| Contexto | Descripción | Líneas | Severidad | CVSS |
|----------|-------------|--------|-----------|------|
| `url_context` | XSS basado en URL/protocolo | 554 | Alta | 7.5 |
| `dom_xss` | XSS basado en DOM (lado cliente) | 359 | Alta | 7.4 |
| `template_injection` | Inyección de plantillas del lado cliente | 116 | Crítica | 8.6 |
| `postmessage_xss` | Vulnerabilidades de API PostMessage | 134 | Alta | 7.4 |
| `wasm_context` | XSS en contexto WebAssembly | 119 | Media | 6.8 |

### Tecnologías Web Modernas
| Contexto | Descripción | Líneas | Severidad | CVSS |
|----------|-------------|--------|-----------|------|
| `websocket_xss` | XSS en tiempo real WebSocket | 431 | Alta | 7.5 |
| `service_worker_xss` | Inyección de Service Worker | 557 | Alta | 7.8 |
| `webrtc_xss` | XSS en comunicación P2P WebRTC | 565 | Alta | 7.6 |
| `indexeddb_xss` | XSS en almacenamiento IndexedDB | 577 | Media | 6.5 |
| `webgl_xss` | Inyección de shader WebGL | 611 | Media | 6.1 |
| `shadow_dom_xss` | Bypass de encapsulación Shadow DOM | 539 | Alta | 7.3 |
| `custom_elements_xss` | XSS en elementos personalizados | 590 | Alta | 7.1 |
| `http2_push_xss` | XSS en push HTTP/2 | 558 | Media | 6.8 |
| `graphql_xss` | Inyección de API GraphQL | 642 | Alta | 7.4 |
| `iframe_sandbox_xss` | Bypass de sandbox iframe | 591 | Media | 6.3 |

### Respaldo
| Contexto | Descripción | Líneas | Severidad | CVSS |
|----------|-------------|--------|-----------|------|
| `default` | Información genérica XSS | 165 | Alta | 7.1 |

</details>

## Características

### Estructura de Metadatos

Cada contexto incluye metadatos de seguridad:

```python
{
 # Información Principal
 "title": "Cross-Site Scripting (XSS) in HTML Content",
 "description": "Explicación detallada de vulnerabilidad...",
 "attack_vector": "Técnicas de ataque del mundo real...",
 "remediation": "Medidas de seguridad accionables...",
 
 # Metadatos de Seguridad
 "severity": "critical", # low | medium | high | critical
 "cvss_score": 8.8, # Puntuación base CVSS 3.1
 "cvss_vector": "CVSS:3.1/...", # Cadena de vector CVSS completa
 "reliability": "certain", # tentative | firm | certain
 "cwe": ["CWE-79"], # Identificadores CWE
 "owasp": ["A03:2021"], # Mapeo OWASP Top 10
 "tags": ["xss", "html", "reflected"] # Etiquetas de clasificación
}
```

### Sistema de Mapeo Inverso Mejorado

Análisis avanzado de payloads con detección automática de contexto y características ML-ready:

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_recommended_defenses, predict_contexts_ml_ready

# Detección automática de contexto con puntuación de confianza
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content'],
# 'severity': 'critical',
# 'confidence': 1.0,
# 'analysis_method': 'pattern_matching',
# 'patterns_matched': 1}

# Detección de contextos XSS modernos
websocket_info = find_contexts_for_payload('WebSocket("wss://evil.com")')
# → {'contexts': ['websocket_xss'], 'severity': 'high', 'confidence': 1.0}

# Análisis ML-ready con extracción de características
ml_analysis = predict_contexts_ml_ready('<script>alert(document.cookie)</script>')
# → {'contexts': ['html_content'], 'features': {'length': 39, 'has_script': True, ...}}

# Mapeo de defensas mejorado con técnicas modernas
defenses = get_recommended_defenses('websocket_xss')
# → [{'defense': 'input_validation', 'priority': 1, 'required': True, 'tags': ['websocket']},
# {'defense': 'csp', 'priority': 1, 'required': True, 'tags': ['policy']}, ...]
```

## Herramienta CLI

BRS-KB incluye una interfaz de línea de comandos integral para investigación de seguridad y pruebas:

```bash
# Instalar el paquete
pip install brs-kb

# Mostrar todos los comandos disponibles
brs-kb --help

# Mostrar información del sistema
brs-kb info

# Listar todos los contextos XSS
brs-kb list-contexts

# Obtener información detallada sobre un contexto
brs-kb get-context websocket_xss

# Analizar un payload
brs-kb analyze-payload "<script>alert(1)</script>"

# Buscar payloads en la base de datos
brs-kb search-payloads websocket --limit 5

# Probar efectividad de payload
brs-kb test-payload "<script>alert(1)</script>" html_content

# Generar reporte integral
brs-kb generate-report

# Validar integridad de base de datos
brs-kb validate

# Exportar datos
brs-kb export contexts --format json --output contexts.json

# Establecer idioma
brs-kb language es

# Migrar a base de datos SQLite
brs-kb migrate

# Iniciar servidor API para Web UI
brs-kb serve

# Iniciar servidor API en puerto personalizado con métricas
brs-kb serve --port 8080 --metrics
```

**Comandos Disponibles:**
- `info` - Mostrar información del sistema y estadísticas
- `list-contexts` - Listar todos los contextos XSS disponibles con severidad
- `get-context <name>` - Obtener información detallada de vulnerabilidad
- `analyze-payload <payload>` - Analizar payload con mapeo inverso
- `search-payloads <query>` - Buscar base de datos payloads con puntuación de relevancia
- `test-payload <payload> <context>` - Probar efectividad de payload en contexto
- `generate-report` - Generar análisis integral del sistema
- `validate` - Validar integridad de base de datos payloads
- `export <type> --format <format>` - Exportar datos (payloads, contexts, reports)
- `language [lang]` - Establecer o listar idiomas soportados (EN, RU, ZH, ES)
- `migrate [--force]` - Migrar payloads a base de datos SQLite
- `serve [--port PORT] [--host HOST] [--metrics]` - Iniciar servidor REST API para Web UI

## Uso

### 1. Integración con Escáner de Seguridad

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

# Usar en escáner
finding = enrich_finding('dom_xss', 'https://target.com/app', 'location.hash')
```

### 2. Integración SIEM/SOC

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

### 3. Reportes Bug Bounty

```python
from brs_kb import get_vulnerability_details

def generate_report(context, url, payload):
 kb = get_vulnerability_details(context)
 
 return f"""
# {kb['title']}

**Severidad**: {kb['severity'].upper()} (CVSS {kb['cvss_score']})
**CWE**: {', '.join(kb['cwe'])}

## URL Vulnerable
{url}

## Prueba de Concepto
```
{payload}
```

## Descripción
{kb['description']}

## Remedio
{kb['remediation']}
"""
```

### 4. Educación y Capacitación

```python
from brs_kb import list_contexts, get_vulnerability_details

# Crear materiales de aprendizaje XSS
for context in list_contexts():
 details = get_vulnerability_details(context)
 
 print(f"Contexto: {context}")
 print(f"Severidad: {details.get('severity', 'N/A')}")
 print(f"Vectores de ataque: {details['attack_vector'][:200]}...")
 print("-" * 80)
```

## Plugins de Escáneres de Seguridad

BRS-KB incluye plugins para herramientas populares de pruebas de seguridad:

### Plugin de Burp Suite
- Análisis de payload XSS en tiempo real durante el proxy
- Detección automática de contexto para solicitudes interceptadas
- Integración con 27 contextos XSS
- Interfaz de equipo de seguridad profesional

**Instalación:** Copiar `plugins/burp_suite/BRSKBExtension.java` a extensiones de Burp

### Integración OWASP ZAP
- Escaneo XSS automatizado con inteligencia BRS-KB
- Inyección de payload consciente del contexto
- Detección de técnicas de bypass de WAF
- Soporte profesional de flujo de trabajo de seguridad

**Instalación:** Cargar `plugins/owasp_zap/brs_kb_zap.py` en scripts de ZAP

### Plantillas Nuclei
- 200+ payloads XSS categorizados
- Pruebas específicas de contexto (27 contextos XSS)
- Detección de técnicas de bypass de WAF

**Instalación:** Copiar plantillas al directorio de plantillas de Nuclei

## Integración SIEM

BRS-KB se integra con sistemas SIEM empresariales para monitoreo y alertas XSS en tiempo real.

| Plataforma | Características | Instalación |
|----------|-------------|--------------|
| **Splunk** | Dashboards, alertas, análisis de tendencias | `siem_connectors/splunk/brs_kb_app.tar.gz` |
| **Elasticsearch** | Dashboards Kibana, detección de anomalías ML | `siem_connectors/elastic/` |
| **Graylog** | Integración GELF, procesamiento de streams | `siem_connectors/graylog/` |

### Configuración Rápida
```bash
# Splunk
cp siem_connectors/splunk/brs_kb_app.tar.gz $SPLUNK_HOME/etc/apps/

# Elasticsearch (Logstash)
cp siem_connectors/elastic/logstash.conf /etc/logstash/conf.d/

# Graylog
# Importar paquete de contenido vía Graylog UI
```

Vea [siem_connectors/README.md](siem_connectors/README.md) para configuración detallada.

## Pipeline CI/CD

BRS-KB incluye configuraciones CI/CD integrales para pruebas y despliegue automatizados:

### GitLab CI (`.gitlab-ci.yml`)
- Pruebas multi-versión de Python (3.8-3.12)
- Chequeos de calidad de código y escaneo de seguridad
- Construcción de paquetes y despliegue PyPI
- Pruebas de rendimiento y reportes de cobertura

### GitLab CI (`.gitlab-ci.yml`) - Configuración Avanzada
- Pruebas paralelas a través de versiones Python
- Construcción de paquetes y despliegue
- Despliegue de documentación (GitLab Pages)
- Pruebas de rendimiento y seguridad

### Pipeline Jenkins (`Jenkinsfile`)
- Pipeline declarativo con ejecución paralela
- Gestión de artefactos y despliegue
- Integración de notificaciones y reportes
- Gestión de pipeline de nivel empresarial

### Script de Configuración (`scripts/setup_cicd.py`)
Configuración automatizada de pipeline CI/CD.

**Configuración Rápida:**
```bash
python3 scripts/setup_cicd.py
```

Vea [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) para documentación detallada de CI/CD.

## Documentación Multi-Idioma

BRS-KB incluye documentación integral en múltiples idiomas:

### Idiomas Disponibles
- **English (EN)** - Documentación principal ([README.md](../README.md))
- **Russian (RU)** - [docs/README.ru.md](README.ru.md)
- **Chinese (ZH)** - [docs/README.zh.md](README.zh.md)
- **Spanish (ES)** - Este archivo

### Cambio de Idioma
```bash
brs-kb language ru    # Cambiar a ruso
brs-kb language zh    # Cambiar a chino
brs-kb language es    # Cambiar a español
brs-kb language en    # Cambiar a inglés
brs-kb language --list  # Listar todos los idiomas soportados
```

### Localización Web UI
El Web UI soporta localización completa en los 4 idiomas:
- Elementos de interfaz localizados
- Ejemplos específicos de contexto
- Adaptación de terminología de seguridad

## Servidor REST API

BRS-KB incluye un servidor REST API integrado para integración Web UI y acceso programático:

### Iniciar el Servidor
```bash
# Iniciar servidor API (por defecto: http://0.0.0.0:8080)
brs-kb serve

# Puerto y host personalizados
brs-kb serve --port 9000 --host 127.0.0.1

# Con endpoint de métricas Prometheus
brs-kb serve --metrics --metrics-port 8000
```

### Endpoints API

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/info` | GET | Información del sistema |
| `/api/health` | GET | Verificación de salud |
| `/api/contexts` | GET | Listar todos los contextos XSS |
| `/api/contexts/<id>` | GET | Obtener detalles del contexto |
| `/api/payloads` | GET | Listar payloads (con filtros) |
| `/api/payloads/search?q=<query>` | GET | Buscar payloads |
| `/api/analyze` | GET/POST | Analizar payload |
| `/api/defenses?context=<ctx>` | GET | Obtener defensas recomendadas |
| `/api/stats` | GET | Estadísticas de la plataforma |
| `/api/languages` | GET | Idiomas soportados |
| `/api/language` | POST | Establecer idioma |

### Python API
```python
from brs_kb import start_api_server, start_metrics_server

# Iniciar servidor API programáticamente
server = start_api_server(port=8080, host='0.0.0.0')

# Iniciar servidor de métricas para Prometheus
metrics = start_metrics_server(port=8000)

# Verificar si está ejecutándose
print(server.is_running())  # True

# Detener servidores
server.stop()
metrics.stop()
```

## Web UI

BRS-KB incluye una interfaz web moderna basada en React para exploración visual y pruebas:

### Interfaz Web (`web_ui/`)
**BRSKB Web UI** - Interfaz web moderna basada en React con integración completa de API

**Características:**
- Exploración visual de 27 contextos XSS
- Playground interactivo para análisis de payloads
- Dashboard de estadísticas en tiempo real
- Navegador de payloads con búsqueda y filtrado
- Visor de documentación API
- Soporte multi-idioma (EN, RU, ZH, ES)
- Diseño responsivo para todos los dispositivos
- Fallback automático cuando API no está disponible

**Páginas:**
- **Home** - Resumen y estadísticas rápidas
- **Contexts** - Navegar todos los contextos de vulnerabilidades XSS
- **Payloads** - Buscar y filtrar 194+ payloads
- **Playground** - Analizador de payloads interactivo
- **Dashboard** - Estadísticas y gráficos
- **API Docs** - Documentación REST API

**Instalación:**
```bash
# Terminal 1: Iniciar servidor API
brs-kb serve --port 8080

# Terminal 2: Iniciar Web UI
cd web_ui
npm install
npm start
```

**Configuración:**
Establecer variable de entorno `REACT_APP_API_URL` para cambiar endpoint API:
```bash
REACT_APP_API_URL=http://localhost:8080/api npm start
```

Vea [web_ui/README.md](web_ui/README.md) para documentación detallada de Web UI.

## Ejemplos

Vea el directorio [examples/](examples/) para ejemplos de integración:

| Ejemplo | Descripción |
|---------|-------------|
| [`basic_usage.py`](examples/basic_usage.py) | Uso básico de API y funcionalidad |
| [`scanner_integration.py`](examples/scanner_integration.py) | Integración en escáneres de seguridad |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | Mapeo inverso mejorado con características ML-ready |
| [`payload_database.py`](examples/payload_database.py) | Base de datos de 194+ payloads con API de pruebas |
| [`cli_demo.py`](examples/cli_demo.py) | Demostración de interfaz de línea de comandos |
| [`plugin_demo.py`](examples/plugin_demo.py) | Integración de plugins de escáner de seguridad |
| [`cicd_demo.py`](examples/cicd_demo.py) | Demostración de pipeline CI/CD |
| [`multilanguage_demo.py`](examples/multilanguage_demo.py) | Demostración de soporte multi-lenguaje |
| [`integrated_demo.py`](examples/integrated_demo.py) | Demostración de integración completa del sistema |

**Ejecutar ejemplos:**
```bash
# Ejemplos Python
python3 examples/basic_usage.py
python3 examples/scanner_integration.py
python3 examples/cli_demo.py
python3 examples/plugin_demo.py
python3 examples/integrated_demo.py

# Comandos CLI
brs-kb info # Información del sistema
brs-kb list-contexts # Todos los contextos XSS
brs-kb get-context websocket_xss # Detalles del contexto
brs-kb analyze-payload "<script>alert(1)</script>" # Análisis de payload
brs-kb search-payloads websocket --limit 5 # Buscar payloads
brs-kb test-payload "<script>alert(1)</script>" html_content # Probar efectividad
brs-kb generate-report # Reporte integral
brs-kb validate # Validación de base de datos
brs-kb export contexts --format json # Exportar datos

# Integración de escáneres de seguridad
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://target.com

# Integración SIEM
python3 siem_connectors/splunk/brs_kb_splunk_connector.py --api-key YOUR_KEY --splunk-url https://splunk.company.com:8088

# Pipeline CI/CD
python3 scripts/setup_cicd.py

# Soporte multi-lenguaje
brs-kb language es
brs-kb language --list
```

## Referencia API

### Funciones Principales

#### `get_vulnerability_details(context: str) -> Dict[str, Any]`
Obtener información detallada sobre contexto de vulnerabilidad.

```python
details = get_vulnerability_details('html_content')
```

#### `list_contexts() -> List[str]`
Obtener lista de todos los contextos disponibles.

```python
contexts = list_contexts() # ['css_context', 'default', 'dom_xss', ...]
```

#### `get_kb_info() -> Dict[str, Any]`
Obtener información de base de conocimientos (versión, build, número de contextos).

```python
info = get_kb_info()
print(f"Version: {info['version']}, Total contexts: {info['total_contexts']}")
```

#### `get_kb_version() -> str`
Obtener cadena de versión.

```python
version = get_kb_version() # "3.0.0"
```

### Funciones de Mapeo Inverso Mejoradas

Importar desde `brs_kb.reverse_map`:

#### `find_contexts_for_payload(payload: str) -> Dict`
Análisis avanzado de payloads con detección automática de contexto y puntuación de confianza.

#### `predict_contexts_ml_ready(payload: str) -> Dict`
Análisis ML-ready con extracción de características para futura integración de machine learning.

#### `get_recommended_defenses(context: str) -> List[Dict]`
Obtener defensas recomendadas para contexto con metadatos mejorados y detalles de implementación.

#### `get_defense_effectiveness(defense: str) -> Dict`
Obtener información integral sobre mecanismo de defensa incluyendo dificultad de bypass y etiquetas.

#### `analyze_payload_with_patterns(payload: str) -> List[Tuple]`
Analizar payload contra base de datos de patrones retornando coincidencias con puntuaciones de confianza.

#### `get_reverse_map_info() -> Dict`
Obtener información del sistema de mapeo inverso incluyendo versión, capacidades y estadísticas.

#### `reverse_lookup(query_type: str, query: str) -> Dict`
Función de búsqueda universal soportando consultas de payload, contexto, defensa y patrón.

### Funciones de Base de Datos de Payloads

#### `get_payloads_by_context(context: str) -> List[Dict]`
Obtener todos los payloads efectivos en contexto específico.

#### `get_payloads_by_severity(severity: str) -> List[Dict]`
Obtener todos los payloads por nivel de severidad.

#### `search_payloads(query: str) -> List[Dict]`
Búsqueda de payloads con puntuación de relevancia.

#### `analyze_payload_context(payload: str, context: str) -> Dict`
Probar efectividad de payload en contexto específico.

#### `get_database_info() -> Dict`
Obtener estadísticas e información de base de datos de payloads.

### Funciones de Herramienta CLI

#### `get_cli() -> BRSKBCLI`
Obtener instancia CLI para uso programático.

**Comandos CLI:**
- `brs-kb info` - Información del sistema
- `brs-kb list-contexts` - Listar todos los contextos XSS
- `brs-kb get-context <name>` - Detalles del contexto
- `brs-kb analyze-payload <payload>` - Análisis de payload
- `brs-kb search-payloads <query>` - Buscar payloads
- `brs-kb test-payload <payload> <context>` - Probar efectividad
- `brs-kb generate-report` - Reporte integral
- `brs-kb validate` - Validación de base de datos
- `brs-kb export <type>` - Exportar datos

## Contribución

Contribuciones de la comunidad de seguridad son bienvenidas.

### Formas de Contribuir

- Agregar nuevos contextos XSS
- Actualizar contextos existentes con nuevos bypass
- Mejorar documentación
- Reportar problemas o información desactualizada
- Compartir ejemplos del mundo real

**Inicio rápido:**
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
git checkout -b feature/new-context
# Hacer cambios
pytest tests/ -v
git commit -m "Add: New context for WebSocket XSS"
git push origin feature/new-context
# Abrir Pull Request
```

Vea [CONTRIBUTING.md](CONTRIBUTING.md) para guías detalladas.

## Estructura del Proyecto

```
BRS-KB/
 brs_kb/ # Paquete principal
 __init__.py # API principal con exportaciones públicas
 api_server.py # Servidor REST API para Web UI
 metrics_server.py # Servidor de métricas Prometheus
 schema.json # Validación JSON Schema
 reverse_map.py # Wrapper de mapeo inverso (compatibilidad hacia atrás)
 reverse_map/ # Paquete de mapeo inverso (modular)
   __init__.py
   patterns.py # Patrones de detección de contexto
   defenses.py # Estrategias de defensa
   analysis.py # Análisis de payloads
   utils.py # Funciones de utilidad
 i18n.py # Sistema de internacionalización
 cli.py # Wrapper CLI (compatibilidad hacia atrás)
 cli/ # Paquete CLI (modular)
   __init__.py
   __main__.py # Punto de entrada de ejecución de módulo
   cli.py # Clase CLI principal
   parser.py # Analizador de argumentos
   commands/ # Módulos de comandos individuales
     base.py # Clase base de comando
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
     serve.py # Comando de servidor API
 payload_testing.py # Framework de pruebas de payloads
 payloads_db.py # Wrapper de base de datos de payloads (compatibilidad hacia atrás)
 payloads_db/ # Paquete de base de datos de payloads (modular)
   __init__.py
   data.py # Base de datos en memoria
   models.py # Modelos de datos
   operations.py # Operaciones CRUD
   queries.py # Funciones de consulta
   search.py # Funcionalidad de búsqueda
   info.py # Información de base de datos
   testing.py # Utilidades de prueba
 payloads_db_sqlite.py # Implementación de base de datos SQLite
 migrations.py # Migraciones de base de datos
 contexts/ # 27 módulos de vulnerabilidades
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # Ejemplos de integración
 tests/ # Suite de pruebas (pytest, 334 pruebas, 81% cobertura)
 docs/ # Documentación multi-idioma
 i18n/locales/ # Archivos de traducción
 plugins/ # Plugins de escáneres de seguridad
 siem_connectors/ # Integraciones de sistemas SIEM
 web_ui/ # Interfaz web basada en React
  src/
    services/api.js # Cliente API para backend
    pages/ # Componentes de página
    components/ # Componentes UI
 LICENSE # Licencia MIT
 CONTRIBUTING.md # Guía de contribución
 CHANGELOG.md # Historial de versiones
 README.md # Este archivo
```

## Pruebas

```bash
# Ejecutar todas las pruebas (334 pruebas)
pytest tests/ -v

# Ejecutar con cobertura (81% cobertura)
pytest tests/ -v --cov=brs_kb --cov-report=term-missing

# Ejecutar módulos de prueba específicos
pytest tests/test_basic.py -v          # Funcionalidad básica
pytest tests/test_cli.py -v            # Comandos CLI
pytest tests/test_sqlite.py -v         # Base de datos SQLite
pytest tests/test_api_server.py -v     # Servidor REST API
pytest tests/test_metrics_server.py -v # Métricas Prometheus
```

**Cobertura de Pruebas:** 81% (334 pruebas pasando)

## Estadísticas

| Métrica | Valor |
|---------|-------|
| Líneas Totales | ~19,500+ |
| Módulos de Contexto | 27 |
| Base de Datos de Payloads | 194+ |
| Cobertura de Pruebas | 81% (334 pruebas) |
| Comandos CLI | 12 comandos |
| Endpoints REST API | 13 |
| Patrones de Mapeo Inverso | 29 |
| Plugins de Escáneres | 3 plataformas |
| Integraciones SIEM | 3 sistemas |
| Soporte Multi-Idioma | 4 idiomas |
| Dependencias Externas | 0 |
| Versión Python | 3.8+ |

### Lista de Verificación de Características

| Característica | Estado |
|---------------|--------|
| Servidor REST API | Soportado |
| Métricas Prometheus | Soportado |
| Web UI (React 18) | Soportado |
| Base de Datos SQLite | Soportado |
| Soporte Multi-Idioma | EN, RU, ZH, ES |
| Soporte Docker | Soportado |
| Soporte Kubernetes | Soportado |
| Pipelines CI/CD | GitHub, GitLab, Jenkins |
| Características ML-Ready | Soportado |
| Detección de Bypass WAF | 15+ payloads |
| Contextos XSS Modernos | WebSocket, WebRTC, GraphQL, etc. |

## Solución de Problemas

### Problemas Comunes

| Problema | Solución |
|---------|----------|
| `ModuleNotFoundError: No module named 'brs_kb'` | Ejecutar `pip install -e .` desde la raíz del proyecto |
| Base de datos SQLite no creada | Ejecutar `brs-kb migrate` o verificar permisos de escritura en `brs_kb/data/` |
| Puerto del servidor API ya en uso | Usar bandera `--port`: `brs-kb serve --port 9000` |
| Web UI no puede conectarse a API | Verificar que el servidor API esté ejecutándose, verificar CORS y `REACT_APP_API_URL` |
| Pruebas fallan en importación | Asegurarse de usar Python 3.8+ |

### Problemas de Base de Datos

```bash
# Forzar recreación de base de datos
brs-kb migrate --force

# Verificar ubicación de base de datos
python3 -c "from brs_kb.payloads_db import get_database_info; print(get_database_info())"

# Verificar integridad de base de datos
brs-kb validate
```

### Problemas del Servidor API

```bash
# Verificar si el puerto está disponible
lsof -i :8080

# Iniciar con registro detallado
brs-kb serve --port 8080 2>&1 | tee server.log

# Probar salud de API
curl http://localhost:8080/api/health
```

### Problemas de Web UI

```bash
# Limpiar caché npm y reinstalar
cd web_ui
rm -rf node_modules package-lock.json
npm install

# Verificar conexión API
curl http://localhost:8080/api/info
```

## Licencia

**Licencia MIT** - Libre para usar en cualquier proyecto (comercial o no comercial)

```
Copyright (c) 2025 EasyProTech LLC / Brabus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

Vea [LICENSE](LICENSE) para el texto completo.

## Información del Proyecto

| | |
|---|---|
| **Proyecto** | BRS-KB (BRS XSS Knowledge Base) |
| **Compañía** | EasyProTech LLC |
| **Sitio Web** | [www.easypro.tech](https://www.easypro.tech) |
| **Desarrollador** | Brabus |
| **Contacto** | [https://t.me/easyprotech](https://t.me/easyprotech) |
| **Repositorio** | [https://github.com/EPTLLC/BRS-KB](https://github.com/EPTLLC/BRS-KB) |
| **Licencia** | MIT |
| **Estado** | Production-Ready |
| **Versión** | 3.0.0 |

## Proyectos Relacionados

- **[BRS-XSS](https://github.com/EPTLLC/brs-xss)** - Advanced XSS Scanner (usa BRS-KB)

## Política de Soporte

**SIN SOPORTE OFICIAL**

Este es un proyecto impulsado por la comunidad. Mientras damos la bienvenida a contribuciones:
- Usar GitHub Issues para reportes de bugs
- Usar Pull Requests para contribuciones
- Sin SLA o tiempo de respuesta garantizado

Este proyecto es mantenido por la comunidad.

## Reconocimientos

- Investigadores de seguridad que contribuyen conocimiento
- Comunidad de código abierto por el soporte
- Todos quienes reportan problemas y mejoras

---

<div align="center">

**Base de Conocimientos XSS de Código Abierto**

*Licencia MIT • Python 3.8+ • Cero Dependencias*

</div>
