"""BYOK providers. Endpoint origins are code constants, never administrator input."""

import os
from contextvars import ContextVar

from .urlscan import UrlscanProvider
from .virustotal import VirusTotalProvider

PROVIDERS = {"virustotal": VirusTotalProvider, "urlscan": UrlscanProvider}
credentials_factory: ContextVar = ContextVar(
    "phishcase_provider_credentials", default=None
)


def credential(name):
    factory = credentials_factory.get()
    if factory is not None:
        return (factory(name) or "").strip()
    return os.environ.get(f"{name.upper()}_API_KEY", "").strip()


def configured(name):
    return name in PROVIDERS and bool(credential(name))


def get_provider(name):
    return PROVIDERS[name](credential(name))
