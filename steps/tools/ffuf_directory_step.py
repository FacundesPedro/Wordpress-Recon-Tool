# recon_wp/steps/tools/ffuf_directory_step.py
"""FFUF directory discovery step.

FFUF (Fuzz Faster U Fool) is a fast web fuzzer that can discover hidden
directories and files on web servers.
"""

from steps.tools.ffuf_base import FfufBaseStep


class FfufDirectoryStep(FfufBaseStep):
    """FFUF directory discovery step."""

    name = "ffuf_directory"
    description = "FFUF directory discovery"
    config_wordlist_key = "ffuf_directory_wordlist"
    wordlist_file = "ffuf/directories.txt"
    url_suffix = "/FUZZ/"
    finding_title = "Directory Found"
    finding_description = "Hidden directory discovered via FFUF fuzzing"
    finding_recommendation = "Review directory contents and access controls"
