"""Which environment is a host in? Checked against a registry, not taken on trust (W4-6).

`environment_class` used to be a string someone typed into app.yaml, and preflight refused only
the literal word "prod". Against real hostnames that one string was the whole safety story: a
typo, or a copied config, and production is scanned as "test".

This module answers two questions for preflight:

- Does a host LOOK like production? `prod_host_patterns` are refused whatever the scope says.
- What class is a host REGISTERED as? A registered host must match the declared class, and a
  shared (test/staging) host must be registered at all.

The registry here is a YAML file — `security/dast/environments.yaml`, or `$DAST_ENV_REGISTRY`.
`lookup(host)` is the whole interface preflight uses, so a real registry (a CMDB, an API) can
replace the file without touching preflight.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "security" / "dast" / "environments.yaml"

# Used only if the shipped file is absent; the file is the place to change them.
_FALLBACK_PROD = ["*.prod.*", "*.prod", "prod.*", "prod-*", "*-prod", "*-prod.*",
                  "*.production.*", "production.*"]


@dataclass
class Registry:
    prod_host_patterns: list[str] = field(default_factory=list)
    hosts: dict[str, str] = field(default_factory=dict)

    def is_production(self, host: str) -> bool:
        host = (host or "").lower()
        return any(fnmatch.fnmatchcase(host, p.lower()) for p in self.prod_host_patterns)

    def lookup(self, host: str) -> str | None:
        """The registered class of `host`: an exact entry first, then the first pattern."""
        host = (host or "").lower()
        exact = {k.lower(): v for k, v in self.hosts.items()}
        if host in exact:
            return str(exact[host]).lower()
        for key, cls in self.hosts.items():
            if any(c in key for c in "*?[") and fnmatch.fnmatchcase(host, key.lower()):
                return str(cls).lower()
        return None


def load(path: str | os.PathLike | None = None) -> Registry:
    """Read the registry. An explicitly named file that does not exist is an error — a typo in
    `$DAST_ENV_REGISTRY` must not silently fall back to "nothing is registered"."""
    import yaml
    explicit = path or os.environ.get("DAST_ENV_REGISTRY")
    p = Path(explicit) if explicit else DEFAULT_PATH
    if not p.exists():
        if explicit:
            raise FileNotFoundError(f"environment registry not found: {p}")
        return Registry(prod_host_patterns=list(_FALLBACK_PROD))
    data = yaml.safe_load(p.read_text()) or {}
    return Registry(prod_host_patterns=list(data.get("prod_host_patterns") or []),
                    hosts=dict(data.get("hosts") or {}))
