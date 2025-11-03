#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Example: BRS-KB Multi-Language Support Demo
Demonstrates localization capabilities across different languages
"""

from brs_kb import (
    get_localized_context,
    set_language,
    get_current_language,
    get_supported_languages,
    get_available_contexts_localized
)


def demonstrate_language_support():
    """Demonstrate multi-language support capabilities."""

    print("🌍 BRS-KB Multi-Language Support Demo")
    print("=" * 60)
    print()

    # Show supported languages
    print("1. Supported Languages:")
    print("-" * 40)
    languages = get_supported_languages()
    current_lang = get_current_language()

    for lang in languages:
        status = " (current)" if lang == current_lang else ""
        print(f"   {lang}{status}")

    print()
    print("✅ Current language:", current_lang)
    print()

    # Demonstrate English content
    print("2. English Content (Default):")
    print("-" * 40)

    context_id = "html_content"
    english_content = get_localized_context(context_id)

    if english_content:
        print(f"Title: {english_content['title']}")
        print(f"Description: {english_content['description'][:100]}...")
        print(f"Examples: {len(english_content.get('examples', []))} available")
    print()

    # Switch to Russian
    print("3. Russian Localization:")
    print("-" * 40)

    if set_language("ru"):
        print("✅ Switched to Russian")
        print(f"🌍 Current language: {get_current_language()}")

        russian_content = get_localized_context(context_id)
        if russian_content:
            print(f"Title: {russian_content['title']}")
            print(f"Description: {russian_content['description'][:100]}...")
            print(f"Examples: {len(russian_content.get('examples', []))} available")
    print()

    # Switch to Chinese
    print("4. Chinese Localization:")
    print("-" * 40)

    if set_language("zh"):
        print("✅ Switched to Chinese")
        print(f"🌍 Current language: {get_current_language()}")

        chinese_content = get_localized_context(context_id)
        if chinese_content:
            print(f"Title: {chinese_content['title']}")
            print(f"Description: {chinese_content['description'][:100]}...")
            print(f"Examples: {len(chinese_content.get('examples', []))} available")
    print()

    # Switch to Spanish
    print("5. Spanish Localization:")
    print("-" * 40)

    if set_language("es"):
        print("✅ Switched to Spanish")
        print(f"🌍 Current language: {get_current_language()}")

        spanish_content = get_localized_context(context_id)
        if spanish_content:
            print(f"Title: {spanish_content['title']}")
            print(f"Description: {spanish_content['description'][:100]}...")
            print(f"Examples: {len(spanish_content.get('examples', []))} available")
    print()

    # Show localized contexts
    print("6. Localized Context List:")
    print("-" * 40)

    set_language("en")  # Reset to English for consistent output

    localized_contexts = get_available_contexts_localized()
    print(f"Available localized contexts: {len(localized_contexts)}")

    for context in localized_contexts[:3]:  # Show first 3
        print(f"   📍 {context['id']}")
        print(f"      Title: {context['title']}")
        print(f"      Description: {context['description']}")
        print()

    # Demonstrate cultural adaptation
    print("7. Cultural Adaptation Examples:")
    print("-" * 40)

    cultural_examples = {
        "en": "Standard XSS examples with common patterns",
        "ru": "Примеры XSS адаптированные для русскоязычных приложений",
        "zh": "针对中文应用程序优化的XSS示例",
        "es": "Ejemplos de XSS adaptados para aplicaciones hispanohablantes"
    }

    print("Cultural adaptation examples:")
    for lang, example in cultural_examples.items():
        print(f"   {lang}: {example}")
    print()

    print("=" * 60)
    print("✅ Multi-language support demonstration complete!")
    print("BRS-KB supports English, Russian, Chinese, and Spanish languages.")
    print("Ready for global security research and international teams.")


def main():
    """Main demonstration function."""
    demonstrate_language_support()


if __name__ == "__main__":
    main()
