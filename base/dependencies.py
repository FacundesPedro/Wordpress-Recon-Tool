# recon_wp/base/dependencies.py
"""
Dependency mixins for standardized external dependency handling.

Provides reusable mixins for:
- WordlistDependencyMixin: Handles wordlist loading with fallback support
- BinaryDependencyMixin: Handles external binary checking with warnings

Usage:
    from base.dependencies import WordlistDependencyMixin, BinaryDependencyMixin

    class MyStep(BaseHttpStep, WordlistDependencyMixin):
        DEFAULT_ITEMS = ["item1", "item2"]

        async def run(self):
            items = self.resolve_wordlist_or_fallback(
                config_key="my_wordlist",
                defaults=self.DEFAULT_ITEMS,
                name="my wordlist",
            )
            if not items:
                return self.findings
            # ... use items
"""

from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

from base.step import BaseStep, BaseToolStep
from utils.wordlist_loader import load_lines

T = TypeVar("T")


class WordlistDependencyMixin:
    """
    Handles wordlist/external file dependency loading with standardized warnings.

    This mixin provides a consistent interface for steps that need external
    wordlists or data files, with graceful fallback to built-in defaults.

    Usage:
        class MyStep(BaseHttpStep, WordlistDependencyMixin):
            DEFAULT_VALUES = ["default1", "default2"]

            async def run(self):
                values = self.resolve_wordlist_or_fallback(
                    config_key="my_wordlist",
                    defaults=self.DEFAULT_VALUES,
                    name="my wordlist",
                    loader=lambda p: self._custom_loader(p),
                )
                # ...

    Attributes:
        WORDLIST_FALLBACK_WARNING: Template for fallback warnings
        WORDLIST_DISABLED_WARNING: Template for disabled step warnings
    """

    WORDLIST_FALLBACK_WARNING = (
        "Wordlist not found at {path}, using limited fallback ({count} items). "
        "For full functionality, provide a wordlist via config or "
        "ensure ~/.config/recon-wp/wordlists/ is set up."
    )

    WORDLIST_DISABLED_WARNING = (
        "Wordlist not configured - step disabled. "
        "To enable: set '{config_key}' key in config or "
        "provide wordlist at ~/.config/recon-wp/wordlists/"
    )

    def resolve_wordlist_or_fallback(
        self: BaseStep,
        config_key: str,
        defaults: Optional[list[Any]] = None,
        name: str = "wordlist",
        loader: Optional[Callable[[Path], list[Any]]] = None,
        custom_path: Optional[str] = None,
    ) -> Optional[list[Any]]:
        """
        Resolve wordlist from config with fallback and standardized warnings.

        Checks for wordlist in the following order:
        1. Config value for config_key
        2. Default wordlist path (~/.config/recon-wp/wordlists/)
        3. Fallback defaults (if provided)
        4. Disabled (return None)

        Args:
            self: Step instance (must be BaseStep or subclass)
            config_key: Key to look up in self.config.keys
            defaults: Fallback list to use if wordlist not found
            name: Human-readable name for logging messages
            loader: Custom loader function that takes Path and returns list
            custom_path: Override path instead of checking config

        Returns:
            List of loaded items, defaults, or None if step should be disabled

        Warnings logged:
            - WARNING if wordlist not found but defaults available
            - WARNING if wordlist required but not configured
        """
        wordlist_path: Optional[str] = None

        if custom_path:
            wordlist_path = custom_path
        elif hasattr(self, "config") and self.config and hasattr(self.config, "keys"):
            wordlist_path = self.config.keys.get(config_key)

        if wordlist_path:
            path = Path(wordlist_path)
            if path.exists() and path.is_file():
                if loader:
                    try:
                        items = loader(path)
                        self.logger.debug(
                            f"Loaded {len(items)} items from {wordlist_path}"
                        )
                        return items
                    except Exception as e:
                        self.logger.warning(f"Error loading {name}: {e}")
                else:
                    return list(load_lines(path))

        if defaults:
            self.logger.warning(
                f"Wordlist not found at {wordlist_path or 'default path'}, "
                f"using limited fallback ({len(defaults)} {name} items). "
                f"For full functionality, provide a wordlist via config."
            )
            return defaults

        self.logger.warning(
            f"No {name} configured - step disabled. "
            f"To enable: set '{config_key}' key in config."
        )
        self._add_disabled_finding(
            title=f"{name.title()} not configured",
            description=f"The {name} was not found and no fallback is available for this check.",
            evidence=f"Missing: {config_key} in config or {wordlist_path}",
            recommendation=f"Configure {name} or set up ~/.config/recon-wp/wordlists/",
        )
        return None

    def _add_disabled_finding(
        self: BaseStep,
        title: str,
        description: str,
        evidence: str,
        recommendation: str,
    ) -> None:
        """Add a finding indicating the step was disabled due to missing dependency."""
        self._add_finding(
            module=getattr(self, "MODULE", "unknown"),
            severity="low",
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            raw={"reason": "dependency_not_configured"},
        )

    def load_credentials_from_wordlist(
        self: BaseStep,
        path: Path,
    ) -> list[tuple[str, str]]:
        """
        Load username:password pairs from a wordlist file.

        Args:
            path: Path to wordlist file

        Returns:
            List of (username, password) tuples
        """
        credentials = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and ":" in line and not line.startswith("#"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            username, password = parts[0].strip(), parts[1].strip()
                            if username and password:
                                credentials.append((username, password))
        except (OSError, FileNotFoundError) as e:
            self.logger.error(f"Error loading credentials from {path}: {e}")
        return credentials

    def resolve_credentials_with_fallback(
        self: BaseStep,
        config_key: str = "wordlist",
    ) -> Optional[list[tuple[str, str]]]:
        """
        Resolve credentials wordlist with fallback for brute force steps.

        Args:
            config_key: Config key for wordlist path (default: "wordlist")

        Returns:
            List of credentials, or None if step should be disabled
        """
        # Default credentials to use as fallback
        default_credentials = [
            ("admin", "password"),
            ("admin", "admin"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("administrator", "password"),
            ("administrator", "admin"),
            ("administrator", "123456"),
            ("user", "password"),
            ("user", "admin"),
            ("user", "123456"),
            ("test", "password"),
            ("test", "test"),
            ("editor", "password"),
            ("editor", "editor"),
            ("author", "password"),
            ("author", "author"),
            ("subscriber", "password"),
            ("subscriber", "subscriber"),
            ("wp", "wp"),
            ("wordpress", "password"),
        ]
        return self.resolve_wordlist_or_fallback(
            config_key=config_key,
            defaults=default_credentials,
            name="credential wordlist",
            loader=self.load_credentials_from_wordlist,
        )


class BinaryDependencyMixin:
    """
    Handles external binary dependency checking with standardized warnings.

    This mixin provides a consistent interface for steps that require
    external command-line tools, with clear messaging about missing binaries.

    Usage:
        class MyToolStep(BaseToolStep, BinaryDependencyMixin):
            _tool_binary = "mytool"
            _install_hint = "brew install mytool"

            async def run(self):
                if not await self.check_binary_with_warning():
                    return self.findings
                # ... proceed
    """

    BINARY_NOT_FOUND_WARNING = (
        "Binary '{binary}' not found in PATH. "
        "This check will be skipped. "
        "To enable: {install_hint}"
    )

    def __init__(
        self: BaseToolStep,
        *args,
        tool_binary: str = "",
        install_hint: str = "",
        **kwargs,
    ):
        """
        Initialize the binary dependency mixin.

        Args:
            tool_binary: Name of the binary (e.g., "nmap", "wpscan")
            install_hint: Installation command hint for users (e.g., "apt install nmap")
        """
        super().__init__(*args, **kwargs)
        self._binary_tool_name = tool_binary or getattr(self, "_tool_binary", "")
        self._binary_install_hint = install_hint or self._get_default_install_hint(
            self._binary_tool_name
        )

    def _get_default_install_hint(self, binary: str) -> str:
        """Get default installation hint based on common package managers."""
        hints = {
            "whois": "brew install whois (macOS) or apt install whois (Linux)",
            "dig": "brew install bind (macOS) or apt install dnsutils (Linux)",
            "nmap": "brew install nmap (macOS) or apt install nmap (Linux)",
            "wpscan": "gem install wpscan",
            "nuclei": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
            "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "amass": "go install github.com/OWASP/Amass/v3/...@latest",
        }
        return hints.get(binary, f"install {binary} via your system package manager")

    async def check_binary_with_warning(
        self: BaseToolStep,
        binary: Optional[str] = None,
        install_hint: Optional[str] = None,
        finding_title: Optional[str] = None,
    ) -> bool:
        """
        Check if a binary exists with standardized warning and finding.

        Args:
            binary: Binary name to check (defaults to self._tool_binary)
            install_hint: Installation hint override
            finding_title: Custom title for the disabled finding

        Returns:
            True if binary exists and is executable, False otherwise
        """
        binary_name = binary or self._binary_tool_name
        hint = install_hint or self._binary_install_hint
        title = finding_title or f"{binary_name.title()} check skipped"

        exists, error = self.check_binary(binary_name)

        if not exists:
            self.logger.warning(
                f"Binary '{binary_name}' not found in PATH. "
                f"This check will be skipped. "
                f"To enable: {hint}"
            )
            self._add_binary_disabled_finding(
                binary=binary_name,
                title=title,
                install_hint=hint,
                error=error,
            )
            return False

        return True

    def _add_binary_disabled_finding(
        self: BaseToolStep,
        binary: str,
        title: str,
        install_hint: str,
        error: str = "",
    ) -> None:
        """Add a finding indicating the step was disabled due to missing binary."""
        self._add_finding(
            module=getattr(self, "MODULE", "unknown"),
            severity="low",
            title=title,
            description=f"The '{binary}' binary is not installed on this system",
            evidence=error or f"Binary '{binary}' not found in PATH",
            recommendation=f"Install {binary}: {install_hint}",
            raw={
                "binary": binary,
                "install_hint": install_hint,
                "reason": "binary_not_found",
            },
        )
