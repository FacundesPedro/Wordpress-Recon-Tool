"""Tests for WordPress slug normalization / validation."""

from utils.slugs import (
    detect_plugins_from_html,
    is_valid_slug,
    normalize_wp_slug,
    normalize_wp_slugs,
)


class TestIsValidSlug:
    def test_accepts_normal_slugs(self):
        for slug in ("akismet", "contact-form-7", "wordpress-seo", "meow-gallery"):
            assert is_valid_slug(slug)

    def test_rejects_html_parse_junk(self):
        assert not is_valid_slug('*","')
        assert not is_valid_slug("a/b")
        assert not is_valid_slug("a b")
        assert not is_valid_slug('"><script>')
        assert not is_valid_slug("")

    def test_rejects_hidden_dot_entries(self):
        assert not is_valid_slug(".git")
        assert not is_valid_slug(".")


class TestNormalizeWpSlug:
    def test_strips_plugin_prefix_and_trailing_slash(self):
        assert normalize_wp_slug("wp-content/plugins/akismet/", "plugins") == "akismet"

    def test_strips_bare_directory_prefix(self):
        assert normalize_wp_slug("plugins/akismet", "plugins") == "akismet"
        assert normalize_wp_slug("themes/default", "themes") == "default"
        assert normalize_wp_slug("themes/default/", "themes") == "default"

    def test_strips_leading_slash(self):
        assert normalize_wp_slug("/wp-content/plugins/akismet", "plugins") == "akismet"

    def test_drops_query_and_fragment(self):
        assert normalize_wp_slug("wp-content/plugins/akismet/?ver=1", "plugins") == "akismet"
        assert normalize_wp_slug("akismet#x", "plugins") == "akismet"

    def test_percent_decodes(self):
        assert normalize_wp_slug("wp-content/plugins/%c2%b5mint/", "plugins") == "µmint"

    def test_comments_and_blanks_dropped(self):
        assert normalize_wp_slug("# comment", "plugins") == ""
        assert normalize_wp_slug("   ", "plugins") == ""
        assert normalize_wp_slug('*","', "plugins") == ""

    def test_does_not_double_strip_real_slug(self):
        # A plugin literally named "themes-xyz" must not lose its prefix.
        assert normalize_wp_slug("themes-xyz", "plugins") == "themes-xyz"


class TestNormalizeWpSlugs:
    def test_dedupes_preserving_order(self):
        out = normalize_wp_slugs(
            ["wp-content/plugins/a/", "a", "b", "#x", "plugins/c"], "plugins"
        )
        assert out == ["a", "b", "c"]

    def test_empty_input(self):
        assert normalize_wp_slugs([], "plugins") == []


class TestDetectPluginsFromHtml:
    def test_extracts_valid_slugs_in_page_order(self):
        html = (
            '<link href="/wp-content/plugins/contact-form-7/includes/css/styles.css">'
            '<script src="/wp-content/plugins/advanced-custom-fields/assets/x.js"></script>'
            '<link href="/wp-content/plugins/contact-form-7/extra.css">'
        )
        assert detect_plugins_from_html(html) == [
            "contact-form-7",
            "advanced-custom-fields",
        ]

    def test_rejects_parse_junk(self):
        # Regression: a broken regex used to leak `*","` into the version and
        # CVE steps (hml-kitsdidaticos A3 / retest #5).
        html = '<a href="/wp-content/plugins/*","/x.css">'
        assert detect_plugins_from_html(html) == []

    def test_ignores_query_and_absolute_urls(self):
        html = (
            '<link href="https://example.com/wp-content/plugins/akismet/a.css?ver=1">'
        )
        assert detect_plugins_from_html(html) == ["akismet"]

    def test_empty_and_none_safe(self):
        assert detect_plugins_from_html("") == []
        assert detect_plugins_from_html(None) == []
