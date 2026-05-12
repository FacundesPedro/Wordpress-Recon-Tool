# recon_wp/base/http_step.py
"""
BaseHttpStep - base class for HTTP-based steps.

Provides HttpClient integration and helper methods for making HTTP requests.
All steps that need to make web requests inherit from this class.
"""

# WHAT: Base class for steps that make HTTP requests to the target
# HOW: Provides fetch(), get(), post(), head() methods and urljoin() helper
# WHY: Encapsulates HTTP logic so individual steps don't repeat request code

import httpx

from base.step import BaseStep
from config import Config
from core.http_client import HttpClient
from core.target import Target


class BaseHttpStep(BaseStep):
    """
    Base class for steps that make HTTP requests.
    Provides HttpClient integration and helper methods.
    """

    MODULE = "base"

    def __init__(
        self,
        target: Target,
        config: Config,
        http: HttpClient,
    ):
        name = getattr(self, "name", self.__class__.__name__)
        description = getattr(self, "description", "")
        super().__init__(
            name=name, target=target, config=config, description=description
        )
        self.http = http

    async def fetch(self, path: str, method: str = "GET", **kwargs) -> httpx.Response:
        """
        Make an HTTP request to the target.

        Args:
            path: URL path to request (will be joined with target.url)
            method: HTTP method
            **kwargs: Additional arguments passed to httpx request

        Returns:
            httpx.Response object
        """
        url = self.target.url.rstrip("/") + "/" + path.lstrip("/")
        return await self.http.request(method, url, **kwargs)

    async def get(self, path: str, **kwargs) -> httpx.Response:
        """Convenience method for GET requests."""
        return await self.fetch(path, "GET", **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response:
        """Convenience method for POST requests."""
        return await self.fetch(path, "POST", **kwargs)

    async def head(self, path: str, **kwargs) -> httpx.Response:
        """Convenience method for HEAD requests."""
        return await self.fetch(path, "HEAD", **kwargs)

    def urljoin(self, path: str) -> str:
        """Join a path to the target URL."""
        base = self.target.url.rstrip("/")
        if path.startswith("/"):
            return base + path
        return base + "/" + path
