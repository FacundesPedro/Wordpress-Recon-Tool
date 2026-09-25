# recon_wp/steps/tools/ffuf_files_step.py
"""FFUF file discovery step.

FFUF (Fuzz Faster U Fool) is a fast web fuzzer that can discover hidden
files on web servers.
"""

from steps.tools.ffuf_base import FfufBaseStep


class FfufFilesStep(FfufBaseStep):
    """FFUF file discovery step."""

    name = "ffuf_files"
    description = "FFUF file discovery"
    wordlist_file = "ffuf/files.txt"
    url_suffix = "/FUZZ"
    finding_title = "File Found"
    finding_description = "Hidden file discovered via FFUF fuzzing"
    finding_recommendation = "Review file contents and access controls"
