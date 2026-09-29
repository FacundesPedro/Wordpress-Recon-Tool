# recon_wp/steps/tools/ffuf_wp_step.py
"""FFUF WordPress-specific path discovery step.

FFUF (Fuzz Faster U Fool) is a fast web fuzzer that can discover
WordPress-specific paths, plugins, and themes.
"""

from steps.tools.ffuf_base import FfufBaseStep


class FfufWpStep(FfufBaseStep):
    """FFUF WordPress-specific path discovery step."""

    name = "ffuf_wp"
    description = "FFUF WordPress-specific path discovery"
    requires = ("wordpress",)
    wp_only = True
    config_wordlist_key = "ffuf_wp_wordlist"
    wordlist_file = "ffuf/wp_paths.txt"
    url_suffix = "/FUZZ"
    finding_title = "WordPress Path Found"
    finding_description = "WordPress-specific path discovered via FFUF fuzzing"
    finding_recommendation = "Review path access controls and functionality"
