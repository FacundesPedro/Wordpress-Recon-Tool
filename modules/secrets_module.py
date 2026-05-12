# recon_wp/modules/secrets_module.py
"""
Secrets module - sensitive file and data exposure.

Checks for exposed configuration files, source control, and debug files.
"""

# WHAT: Looks for exposed secrets (wp-config backups, .env, .git, debug logs, phpinfo)
# HOW: Attempts to fetch known sensitive file paths
# WHY: Exposed files can contain database credentials, API keys, source code
# STEPS: WpConfigBackupStep, EnvFileStep, GitExposureStep, DebugLogStep, PhpinfoStep

from modules.module import Module
from steps.secrets import (
    DebugLogStep,
    EnvFileStep,
    GitExposureStep,
    PhpinfoStep,
    WpConfigBackupStep,
)


class SecretsModule(Module):
    name = "secrets"
    description = (
        "Secrets exposure checks (wp-config backup, env file, git, debug log, phpinfo)"
    )

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(WpConfigBackupStep)
        self.add_step(EnvFileStep)
        self.add_step(GitExposureStep)
        self.add_step(DebugLogStep)
        self.add_step(PhpinfoStep)
