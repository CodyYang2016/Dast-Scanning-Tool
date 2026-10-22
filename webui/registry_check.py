"""The environment registry check the UI applies before onboarding or starting a run.

It refuses what the runner's preflight would refuse later — production-like hosts, and test or
staging hosts nobody registered — so the person hears it at once, in one sentence. The runner's
own preflight still runs: this is an earlier layer, not a replacement.
"""
from __future__ import annotations

from urllib.parse import urlparse

from runner import env_registry


def refusal(registry_path, base_url: str, environment_class: str) -> tuple[str, str] | None:
    """(message, fix) when the host may not be scanned as that class, else None."""
    host = (urlparse(base_url or "").hostname or "").lower()
    if not host:
        return ("The application's address doesn't name a host.",
                "Set its address to something like https://app.test.example.internal.")
    registry = env_registry.load(registry_path)
    if registry.is_production(host):
        return (f"{host} looks like a production system, so it can't be scanned.",
                "Scan a dev, test or staging copy instead.")
    registered = registry.lookup(host)
    if environment_class in ("test", "staging") and registered != environment_class:
        if registered is None:
            return (f"{host} isn't in the environment registry, so the tool can't confirm it's a "
                    f"{environment_class} system.",
                    f"Ask Governance to add {host} as {environment_class} in the environment registry.")
        return (f"{host} is registered as {registered}, not {environment_class}.",
                f"Change the app's environment to {registered}, or ask Governance to correct the registry.")
    return None
