#!/usr/bin/env python3

"""
BRS-KB Modern i18n/L10n System
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Modern internationalization system using JSON files for better maintainability
"""

import json
import os
from typing import Dict, List, Any, Optional


class I18nManager:
    """Modern i18n/L10n manager using JSON files"""

    def __init__(self, locales_dir: Optional[str] = None):
        """Initialize i18n manager"""
        self.locales_dir: Optional[str]
        if locales_dir is None:
            # Try to find locales in multiple possible locations
            current_dir = os.path.dirname(__file__)

            # First, try relative to current file (development)
            self.locales_dir = os.path.join(current_dir, "..", "i18n", "locales")

            # If not found, try relative to package (installed)
            if not os.path.exists(self.locales_dir):
                self.locales_dir = os.path.join(current_dir, "i18n", "locales")

            # If still not found, try absolute path from project root
            if not os.path.exists(self.locales_dir):
                project_root = os.path.join(current_dir, "..", "..", "..")
                self.locales_dir = os.path.join(project_root, "i18n", "locales")

            # Final fallback - use embedded translations
            if not os.path.exists(self.locales_dir):
                self.locales_dir = None
        else:
            self.locales_dir = locales_dir

        self.current_language = "en"
        self.supported_languages = ["en", "ru", "zh", "es"]
        self.translations = self._load_translations()

    def _load_translations(self) -> Dict[str, Dict[str, Any]]:
        """Load all translation files"""
        translations = {}

        # If no locales directory found, use embedded translations
        if self.locales_dir is None:
            translations = self._get_embedded_translations()
        else:
            for lang in self.supported_languages:
                file_path = os.path.join(self.locales_dir, f"{lang}.json")
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        translations[lang] = json.load(f)
                except FileNotFoundError:
                    print(f"Warning: Translation file not found: {file_path}")
                    translations[lang] = {}
                except json.JSONDecodeError as e:
                    print(f"Error loading translation file {file_path}: {e}")
                    translations[lang] = {}

        return translations

    def _get_embedded_translations(self) -> Dict[str, Dict[str, Any]]:
        """Get embedded fallback translations"""
        return {
            "en": {
                "app": {
                    "name": "BRS-KB XSS Knowledge Base",
                    "description": "Advanced XSS Intelligence Database for Researchers and Scanners",
                    "version": "Version",
                    "loading": "Loading...",
                    "error": "Error",
                    "success": "Success",
                    "warning": "Warning",
                    "info": "Information",
                },
                "navigation": {
                    "home": "Home",
                    "contexts": "Contexts",
                    "payloads": "Payloads",
                    "playground": "Playground",
                    "dashboard": "Dashboard",
                    "api_docs": "API Docs",
                },
                "contexts": {
                    "title": "XSS Vulnerability Contexts",
                    "description": "Explore different XSS vulnerability contexts with detailed attack vectors and remediation strategies.",
                    "severity": "Severity",
                    "cvss_score": "CVSS Score",
                    "description": "Description",
                    "attack_vector": "Attack Vector",
                    "remediation": "Remediation",
                    "examples": "Examples",
                    "payload_count": "Payload Count",
                },
                "common": {
                    "loading": "Loading...",
                    "error": "Error",
                    "success": "Success",
                    "warning": "Warning",
                    "info": "Information",
                    "total": "Total",
                    "yes": "Yes",
                    "no": "No",
                },
            },
            "ru": {
                "app": {
                    "name": "BRS-KB База Знаний XSS",
                    "description": "Расширенная база данных XSS для исследователей и сканеров",
                    "version": "Версия",
                    "loading": "Загрузка...",
                    "error": "Ошибка",
                    "success": "Успех",
                    "warning": "Предупреждение",
                    "info": "Информация",
                },
                "navigation": {
                    "home": "Главная",
                    "contexts": "Контексты",
                    "payloads": "Payloads",
                    "playground": "Площадка",
                    "dashboard": "Панель",
                    "api_docs": "API Документация",
                },
                "contexts": {
                    "title": "Контексты XSS Уязвимостей",
                    "description": "Изучите различные контексты XSS уязвимостей с детальными векторами атак и стратегиями исправления.",
                    "severity": "Серьезность",
                    "cvss_score": "CVSS Счет",
                    "description": "Описание",
                    "attack_vector": "Вектор Атаки",
                    "remediation": "Исправление",
                    "examples": "Примеры",
                    "payload_count": "Количество Payloads",
                },
                "common": {
                    "loading": "Загрузка...",
                    "error": "Ошибка",
                    "success": "Успех",
                    "warning": "Предупреждение",
                    "info": "Информация",
                    "total": "Всего",
                    "yes": "Да",
                    "no": "Нет",
                },
            },
            "zh": {
                "app": {
                    "name": "BRS-KB XSS 知识库",
                    "description": "研究人员和扫描器的先进 XSS 情报数据库",
                    "version": "版本",
                    "loading": "加载中...",
                    "error": "错误",
                    "success": "成功",
                    "warning": "警告",
                    "info": "信息",
                },
                "navigation": {
                    "home": "主页",
                    "contexts": "上下文",
                    "payloads": "Payloads",
                    "playground": "测试场",
                    "dashboard": "仪表板",
                    "api_docs": "API 文档",
                },
                "contexts": {
                    "title": "XSS 漏洞上下文",
                    "description": "探索具有详细攻击向量和修复策略的不同 XSS 漏洞上下文。",
                    "severity": "严重性",
                    "cvss_score": "CVSS 分数",
                    "description": "描述",
                    "attack_vector": "攻击向量",
                    "remediation": "修复",
                    "examples": "示例",
                    "payload_count": "Payload 数量",
                },
                "common": {
                    "loading": "加载中...",
                    "error": "错误",
                    "success": "成功",
                    "warning": "警告",
                    "info": "信息",
                    "total": "总计",
                    "yes": "是",
                    "no": "否",
                },
            },
            "es": {
                "app": {
                    "name": "BRS-KB Base de Conocimientos XSS",
                    "description": "Base de datos de inteligencia XSS avanzada para investigadores y escáneres",
                    "version": "Versión",
                    "loading": "Cargando...",
                    "error": "Error",
                    "success": "Éxito",
                    "warning": "Advertencia",
                    "info": "Información",
                },
                "navigation": {
                    "home": "Inicio",
                    "contexts": "Contextos",
                    "payloads": "Payloads",
                    "playground": "Terreno de Pruebas",
                    "dashboard": "Panel",
                    "api_docs": "Documentación API",
                },
                "contexts": {
                    "title": "Contextos de Vulnerabilidades XSS",
                    "description": "Explore diferentes contextos de vulnerabilidades XSS con vectores de ataque detallados y estrategias de remediación.",
                    "severity": "Severidad",
                    "cvss_score": "Puntuación CVSS",
                    "description": "Descripción",
                    "attack_vector": "Vector de Ataque",
                    "remediation": "Remediación",
                    "examples": "Ejemplos",
                    "payload_count": "Número de Payloads",
                },
                "common": {
                    "loading": "Cargando...",
                    "error": "Error",
                    "success": "Éxito",
                    "warning": "Advertencia",
                    "info": "Información",
                    "total": "Total",
                    "yes": "Sí",
                    "no": "No",
                },
            },
        }

    def set_language(self, language: str) -> bool:
        """Set current language"""
        if language in self.supported_languages:
            self.current_language = language
            return True
        return False

    def get_current_language(self) -> str:
        """Get current language"""
        return self.current_language

    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages"""
        return self.supported_languages.copy()

    def t(self, key: str, **kwargs) -> str:
        """
        Translate string with interpolation support

        Args:
            key: Translation key (e.g., "app.name")
            **kwargs: Variables for interpolation

        Returns:
            Translated and interpolated string
        """
        translation = self.translations.get(self.current_language, {})
        keys = key.split(".")

        # Navigate through nested structure
        value: Any = translation
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                value = None
                break

        if value is None:
            # Fallback to English
            fallback = self.translations.get("en", {})
            value = fallback
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return key  # Return key as fallback

        # Handle interpolation
        if isinstance(value, str):
            try:
                return value.format(**kwargs)
            except KeyError:
                return value  # Return as-is if interpolation fails

        return str(value) if value is not None else key

    def get_context_details(self, context_id: str) -> Dict[str, Any]:
        """Get localized context details"""
        translation = self.translations.get(self.current_language, {})
        contexts = translation.get("context_details", {})
        if not isinstance(contexts, dict):
            contexts = {}

        if context_id in contexts:
            result = contexts[context_id]
            if isinstance(result, dict):
                return result
            return {}

        # Fallback to English
        fallback = self.translations.get("en", {})
        fallback_contexts = fallback.get("context_details", {})
        if not isinstance(fallback_contexts, dict):
            fallback_contexts = {}
        result = fallback_contexts.get(context_id, {})
        return result if isinstance(result, dict) else {}

    def get_app_info(self) -> Dict[str, str]:
        """Get localized app information"""
        translation = self.translations.get(self.current_language, {})
        app_info = translation.get("app", {})
        return app_info if isinstance(app_info, dict) else {}

    def get_common_strings(self) -> Dict[str, str]:
        """Get common UI strings"""
        translation = self.translations.get(self.current_language, {})
        common = translation.get("common", {})
        return common if isinstance(common, dict) else {}

    def get_navigation(self) -> Dict[str, str]:
        """Get navigation strings"""
        translation = self.translations.get(self.current_language, {})
        navigation = translation.get("navigation", {})
        return navigation if isinstance(navigation, dict) else {}


# Global i18n manager instance
_i18n_manager = I18nManager()


def set_language(language: str) -> bool:
    """Set global language"""
    return _i18n_manager.set_language(language)


def get_current_language() -> str:
    """Get current language"""
    return _i18n_manager.get_current_language()


def get_supported_languages() -> List[str]:
    """Get supported languages"""
    return _i18n_manager.get_supported_languages()


def t(key: str, **kwargs) -> str:
    """Translate string with interpolation"""
    return _i18n_manager.t(key, **kwargs)


def get_context_details(context_id: str) -> Dict[str, Any]:
    """Get localized context details"""
    return _i18n_manager.get_context_details(context_id)


def get_app_info() -> Dict[str, str]:
    """Get localized app information"""
    return _i18n_manager.get_app_info()


def get_common_strings() -> Dict[str, str]:
    """Get common UI strings"""
    return _i18n_manager.get_common_strings()


def get_navigation() -> Dict[str, str]:
    """Get navigation strings"""
    return _i18n_manager.get_navigation()


# Export functions
__all__ = [
    "I18nManager",
    "set_language",
    "get_current_language",
    "get_supported_languages",
    "t",
    "get_context_details",
    "get_app_info",
    "get_common_strings",
    "get_navigation",
]
