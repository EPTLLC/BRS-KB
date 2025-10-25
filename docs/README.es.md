# BRS-KB

### Base de Conocimientos XSS de la Comunidad

**Conocimiento Abierto para la Comunidad de Seguridad**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-16.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-passing-success.svg)]()

Base de conocimientos integral y comunitaria para vulnerabilidades de Cross-Site Scripting (XSS)

[Características](#-características) • [Instalación](#-instalación) • [Uso](#-uso) • [API](#-referencia-api) • [Ejemplos](#-ejemplos) • [Contribución](#-contribución)

---

## ¿Por qué BRS-KB?

| Característica | Descripción |
|---------------|-------------|
| **27 Contextos** | Cobertura de tipos clásicos y modernos de vulnerabilidades XSS |
| **Información Detallada** | Vectores de ataque, técnicas de bypass, estrategias de defensa |
| **API Simple** | Biblioteca Python, fácil integración |
| **Cero Dependencias** | Python puro 3.8+ |
| **Compatible con SIEM** | Puntuaciones CVSS, mapeos CWE/OWASP, niveles de severidad |
| **Código Abierto** | Licencia MIT, contribuciones comunitarias bienvenidas |
| **En Producción** | Usado en escáneres de seguridad y herramientas |

## Instalación

```bash
pip install brs-kb
```

**Desde el código fuente:**
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e .
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
| Contexto | Descripción | Líneas | Severidad |
|----------|-------------|--------|-----------|
| `html_content` | XSS en contenido HTML | 398 | Crítica |
| `html_attribute` | XSS en atributos HTML | 529 | Crítica |
| `html_comment` | XSS en comentarios HTML | 68 | Media |

### Contextos JavaScript
| Contexto | Descripción | Líneas | Severidad |
|----------|-------------|--------|-----------|
| `javascript_context` | Inyección directa de JavaScript | 636 | Crítica |
| `js_string` | Inyección de cadena JavaScript | 619 | Crítica |
| `js_object` | Inyección de objeto JavaScript | 619 | Alta |

### Estilo y Marcado
| Contexto | Descripción | Líneas | Severidad |
|----------|-------------|--------|-----------|
| `css_context` | Inyección CSS y atributos de estilo | 675 | Alta |
| `svg_context` | Vectores XSS basados en SVG | 288 | Alta |
| `markdown_context` | XSS en renderizado Markdown | 101 | Media |

### Formatos de Datos
| Contexto | Descripción | Líneas | Severidad |
|----------|-------------|--------|-----------|
| `json_value` | XSS en contexto JSON | 72 | Media |
| `xml_content` | Vectores XSS XML/XHTML | 81 | Alta |

### Vectores Avanzados
| Contexto | Descripción | Líneas | Severidad |
|----------|-------------|--------|-----------|
| `url_context` | XSS basado en URL/protocolo | 545 | Alta |
| `dom_xss` | XSS basado en DOM (lado cliente) | 350 | Alta |
| `template_injection` | Inyección de plantillas del lado cliente | 107 | Crítica |
| `postmessage_xss` | Vulnerabilidades de API PostMessage | 125 | Alta |
| `wasm_context` | XSS en contexto WebAssembly | 110 | Media |

### Tecnologías Web Modernas (NUEVO)
| Contexto | Descripción | Líneas | Severidad |
|----------|-------------|--------|-----------|
| `websocket_xss` | XSS en tiempo real WebSocket | 407 | Alta |
| `service_worker_xss` | Inyección de Service Worker | 398 | Alta |
| `webrtc_xss` | XSS en comunicación P2P WebRTC | 420 | Alta |
| `indexeddb_xss` | XSS en almacenamiento IndexedDB | 378 | Media |
| `webgl_xss` | Inyección de shader WebGL | 395 | Media |
| `shadow_dom_xss` | Bypass de encapsulación Shadow DOM | 385 | Alta |
| `custom_elements_xss` | XSS en elementos personalizados | 390 | Alta |
| `http2_push_xss` | XSS en push HTTP/2 | 375 | Media |
| `graphql_xss` | Inyección de API GraphQL | 390 | Alta |
| `iframe_sandbox_xss` | Bypass de sandbox iframe | 380 | Media |

### Respaldo
| Contexto | Descripción | Líneas | Severidad |
|----------|-------------|--------|-----------|
| `default` | Información genérica XSS | 156 | - |

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

### Sistema de Mapeo Inverso

Mapear payloads a contextos y defensas:

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_defenses_for_context

# Mapeo Payload → Context
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content', 'html_comment', 'svg_context'],
# 'severity': 'critical',
# 'defenses': ['html_encoding', 'csp', 'sanitization']}

# Mapeo Context → Defense
defenses = get_defenses_for_context('html_content')
# → [{'defense': 'html_encoding', 'priority': 1, 'required': True},
# {'defense': 'csp', 'priority': 1, 'required': True}, ...]
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
- Pruebas de tecnologías web modernas

**Instalación:** Copiar plantillas al directorio de plantillas de Nuclei

Vea [plugins/README.md](plugins/README.md) para instrucciones detalladas de instalación y uso.

## Integración SIEM

BRS-KB se integra con sistemas SIEM empresariales para monitoreo en tiempo real:

#### Integración Splunk
- Ingestión de datos de vulnerabilidades XSS en tiempo real
- Dashboards personalizados para análisis de contexto XSS
- Reglas de alerta para vulnerabilidades críticas
- Análisis histórico de tendencias

**Instalación:** Copiar `siem_connectors/splunk/brs_kb_app.tar.gz` al directorio de apps de Splunk

#### Integración Elasticsearch
- Integración Logstash/Beats para datos BRS-KB
- Dashboards Kibana para análisis XSS
- Detección de anomalías de machine learning
- Alertas de Elasticsearch Watcher

**Instalación:** Desplegar configuración Logstash desde `siem_connectors/elastic/`

#### Integración Graylog
- Integración GELF para ingestión de logs en tiempo real
- Dashboards y widgets personalizados
- Reglas de alerta y notificaciones
- Procesamiento de streams para eventos XSS

**Instalación:** Importar paquete de contenido desde `siem_connectors/graylog/`

Vea [siem_connectors/README.md](siem_connectors/README.md) para instrucciones detalladas de instalación y uso.

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

## Ejemplos

Vea el directorio [examples/](examples/) para ejemplos de integración:

| Ejemplo | Descripción |
|---------|-------------|
| [`basic_usage.py`](examples/basic_usage.py) | Uso básico de API y funcionalidad |
| [`scanner_integration.py`](examples/scanner_integration.py) | Integración en escáneres de seguridad |
| [`siem_integration.py`](examples/siem_integration.py) | Inteligencia de amenazas SIEM/SOC |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | Mapeo inverso mejorado con características ML-ready |
| [`payload_database.py`](examples/payload_database.py) | Base de datos de 200+ payloads con API de pruebas |
| [`cli_demo.py`](examples/cli_demo.py) | Demostración de interfaz de línea de comandos |
| [`plugin_demo.py`](examples/plugin_demo.py) | Integración de plugins de escáner de seguridad |
| [`siem_integration.py`](examples/siem_integration.py) | Demostración de integración de sistemas SIEM |
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
brs-kb analyze-payload "<script>alert(1)</script>" # Análisis de payload
brs-kb search-payloads websocket # Buscar payloads
brs-kb generate-report # Reporte integral

# Integración de escáneres de seguridad
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://target.com

# Integración SIEM
python3 siem_connectors/splunk/brs_kb_splunk_connector.py --api-key YOUR_KEY --splunk-url https://splunk.company.com:8088

# Pipeline CI/CD
python3 scripts/setup_cicd.py

# Soporte multi-lenguaje
brs-kb language ru
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
version = get_kb_version() # "2.0.0"
```

### Funciones de Mapeo Inverso Mejoradas

Importar desde `brs_kb.reverse_map`:

#### `find_contexts_for_payload(payload: str) -> Dict`
Análisis avanzado de payload con detección automática de contexto y puntuación de confianza.

#### `predict_contexts_ml_ready(payload: str) -> Dict`
Análisis ML-ready con extracción de características para futura integración de machine learning.

#### `get_defenses_for_context(context: str) -> List[Dict]`
Obtener defensas recomendadas para contexto con metadatos mejorados y detalles de implementación.

#### `get_defense_info(defense: str) -> Dict`
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

#### `test_payload_in_context(payload: str, context: str) -> Dict`
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
 __init__.py # API principal
 schema.json # Validación JSON Schema
 reverse_map.py # Sistema de mapeo inverso
 i18n.py # Sistema de internacionalización
 cli.py # Interfaz de línea de comandos
 payload_testing.py # Framework de pruebas de payloads
 payloads_db.py # Base de datos de payloads
 contexts/ # 27 módulos de vulnerabilidades
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # Ejemplos de integración
 tests/ # Suite de pruebas (pytest)
 docs/ # Documentación multi-idioma
 i18n/locales/ # Archivos de traducción
 plugins/ # Plugins de escáneres de seguridad
 siem_connectors/ # Integraciones de sistemas SIEM
 web_ui/ # Interfaz web basada en React
 LICENSE # Licencia MIT
 CONTRIBUTING.md # Guía de contribución
 CHANGELOG.md # Historial de versiones
 README.md # Este archivo
```

## Pruebas

```bash
# Ejecutar todas las pruebas
pytest tests/ -v

# Ejecutar con cobertura (requiere pytest-cov)
pytest tests/ -v --cov=brs_kb

# Ejecutar prueba específica
pytest tests/test_basic.py -v
```

## Estadísticas

| Métrica | Valor |
|---------|-------|
| Líneas Totales | ~16,500+ |
| Módulos de Contexto | 27 |
| Base de Datos de Payloads | 200+ |
| Patrones de Mapeo Inverso | 29 |
| Contextos Soportados | 27 |
| Tamaño Promedio de Módulo | 418 líneas |
| Cobertura de Pruebas | 33 pruebas |
| Comandos CLI | 9 comandos |
| Plugins de Escáneres | 3 plataformas |
| Integraciones SIEM | 3 sistemas |
| Pipelines CI/CD | GitLab CI, Jenkins |
| Scripts de Despliegue | |
| Soporte Docker | |
| Soporte Kubernetes | |
| Monitoreo | |
| Soporte Multi-Idioma | |
| Localización Rusa | |
| Localización China | |
| Localización Española | |
| Dependencias Externas | 0 |
| Versión Python | 3.8+ |
| Calidad de Código | Production-ready |
| ML Ready | |
| Puntuación de Confianza | |
| Soporte XSS Moderno | |
| WebSocket XSS | |
| Service Worker XSS | |
| WebRTC XSS | |
| GraphQL XSS | |
| Shadow DOM XSS | |
| Custom Elements XSS | |
| API de Pruebas de Payloads | |
| Detección de Bypass WAF | |
| Herramienta CLI | |
| Capacidades de Exportación | |
| Plugins de Escáneres de Seguridad | |
| Integración Burp Suite | |
| Integración OWASP ZAP | |
| Plantillas Nuclei | |
| Conectores SIEM | |
| Integración Splunk | |
| Integración Elasticsearch | |
| Integración Graylog | |
| Automatización CI/CD | |
| GitLab CI | |
| Pipeline Jenkins | |
| Soporte Multi-Idioma | |
| Localización Rusa | |
| Localización China | |
| Localización Española | |

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
| **Versión** | 2.0.0 |

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

[Estrella en GitHub](https://github.com/EPTLLC/BRS-KB) • [Reportar Bug](https://github.com/EPTLLC/BRS-KB/issues) • [Solicitar Característica](https://github.com/EPTLLC/BRS-KB/issues)

</div>
