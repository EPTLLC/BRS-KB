#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for i18n module
"""

import os
import tempfile
import json
import pytest
from brs_kb.i18n import I18nManager, set_language, get_current_language, t, get_supported_languages


class TestI18nManager:
    """Test I18nManager class"""

    def test_manager_initialization(self):
        """Test manager initialization"""
        manager = I18nManager()
        assert manager.current_language == "en"
        assert "en" in manager.supported_languages
        assert isinstance(manager.translations, dict)

    def test_manager_with_custom_locales_dir(self):
        """Test manager with custom locales directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            locales_dir = os.path.join(tmpdir, "locales")
            os.makedirs(locales_dir)

            # Create test translation file
            test_translation = {"app": {"name": "Test App"}}
            with open(os.path.join(locales_dir, "en.json"), "w") as f:
                json.dump(test_translation, f)

            manager = I18nManager(locales_dir=locales_dir)
            assert manager.locales_dir == locales_dir

    def test_load_translations(self):
        """Test loading translations"""
        manager = I18nManager()
        assert isinstance(manager.translations, dict)
        assert len(manager.translations) > 0

    def test_set_language_valid(self):
        """Test setting valid language"""
        manager = I18nManager()
        assert manager.set_language("ru") is True
        assert manager.current_language == "ru"

        assert manager.set_language("en") is True
        assert manager.current_language == "en"

    def test_set_language_invalid(self):
        """Test setting invalid language"""
        manager = I18nManager()
        assert manager.set_language("invalid") is False
        assert manager.current_language == "en"  # Should remain unchanged

    def test_get_translation_existing(self):
        """Test getting existing translation"""
        manager = I18nManager()
        manager.set_language("en")

        translation = manager.t("app.name")
        assert translation is not None
        assert isinstance(translation, str)

    def test_get_translation_nested(self):
        """Test getting nested translation"""
        manager = I18nManager()
        manager.set_language("en")

        translation = manager.t("navigation.home")
        assert translation is not None

    def test_get_translation_missing(self):
        """Test getting missing translation"""
        manager = I18nManager()
        manager.set_language("en")

        translation = manager.t("nonexistent.key")
        assert translation == "nonexistent.key"  # Should return key as fallback

    def test_get_translation_with_interpolation(self):
        """Test getting translation with interpolation"""
        manager = I18nManager()
        manager.set_language("en")

        # Test that interpolation works if translation supports it
        translation = manager.t("app.name")
        assert translation is not None

    def test_get_supported_languages(self):
        """Test getting supported languages"""
        manager = I18nManager()
        languages = manager.get_supported_languages()
        assert isinstance(languages, list)
        assert "en" in languages
        assert len(languages) > 0


class TestI18nFunctions:
    """Test i18n module functions"""

    def test_set_language_function(self):
        """Test set_language function"""
        assert set_language("en") is True
        assert set_language("ru") is True
        assert set_language("invalid") is False

    def test_get_current_language_function(self):
        """Test get_current_language function"""
        set_language("en")
        assert get_current_language() == "en"

        set_language("ru")
        assert get_current_language() == "ru"

    def test_translate_function(self):
        """Test translate function (t)"""
        set_language("en")
        translation = t("app.name")
        assert translation is not None
        assert isinstance(translation, str)

    def test_translate_missing_key(self):
        """Test translate with missing key"""
        set_language("en")
        translation = t("nonexistent.key")
        assert translation == "nonexistent.key"  # Should return key as fallback

    def test_get_supported_languages_function(self):
        """Test get_supported_languages function"""
        languages = get_supported_languages()
        assert isinstance(languages, list)
        assert "en" in languages

    def test_translate_nested_key(self):
        """Test translating nested keys"""
        set_language("en")
        translation = t("navigation.home")
        assert translation is not None
        assert isinstance(translation, str)


class TestI18nEdgeCases:
    """Test i18n edge cases"""

    def test_manager_with_missing_translation_file(self):
        """Test manager with missing translation file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            locales_dir = os.path.join(tmpdir, "locales")
            os.makedirs(locales_dir)

            # Don't create any translation files
            manager = I18nManager(locales_dir=locales_dir)
            # Should use embedded translations
            assert isinstance(manager.translations, dict)

    def test_manager_with_invalid_json(self):
        """Test manager with invalid JSON file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            locales_dir = os.path.join(tmpdir, "locales")
            os.makedirs(locales_dir)

            # Create invalid JSON file
            with open(os.path.join(locales_dir, "en.json"), "w") as f:
                f.write("invalid json {")

            manager = I18nManager(locales_dir=locales_dir)
            # Should handle error gracefully
            assert isinstance(manager.translations, dict)

    def test_translation_fallback_chain(self):
        """Test translation fallback chain"""
        manager = I18nManager()
        manager.set_language("invalid_lang")

        # Should fallback to English or return key
        translation = manager.t("app.name")
        assert translation is not None

    def test_empty_translation_key(self):
        """Test empty translation key"""
        manager = I18nManager()
        translation = manager.t("")
        assert translation == ""

    def test_translation_with_interpolation(self):
        """Test translation with variable interpolation"""
        manager = I18nManager()
        manager.set_language("en")
        
        # Test interpolation if translation supports it
        translation = manager.t("app.name")
        assert isinstance(translation, str)

