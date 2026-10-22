"""Resolve which tier each app.yaml setting is in, for one app (UI-N7).

The mapping is data (tiers.yaml); this only applies it. Anything the mapping doesn't know is
tier C and not editable: the UI fails closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Tier:
    tier: str
    editable: bool
    label: str
    help: str
    owner: str

    def as_dict(self) -> dict:
        return {"tier": self.tier, "editable": self.editable, "label": self.label,
                "help": self.help, "owner": self.owner}


UNKNOWN = Tier("C", False, "", "Not in the tier mapping, so it can't be changed here.", "GOV")


class TierMap:
    def __init__(self, path: Path):
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        self.entries = {f["path"]: f for f in data.get("fields") or []}
        self.postures = list(data.get("postures") or [])

    def entry_for(self, dotted: str) -> dict | None:
        """The entry for a path: an exact one, else the nearest ancestor marked prefix or whole."""
        if dotted in self.entries:
            return self.entries[dotted]
        parts = dotted.split(".")
        for i in range(len(parts) - 1, 0, -1):
            parent = self.entries.get(".".join(parts[:i]))
            if parent and (parent.get("prefix") or parent.get("whole")):
                return parent
        return None

    def is_whole(self, dotted: str) -> bool:
        e = self.entries.get(dotted)
        return bool(e and e.get("whole"))

    def resolve(self, dotted: str, cfg: dict) -> Tier:
        e = self.entry_for(dotted)
        if e is None:
            return UNKNOWN
        tier = e["tier"]
        facts = {"environment_class": cfg.get("environment_class"),
                 "data_policy": cfg.get("data_policy") or "durable"}
        for rule in e.get("when") or []:
            conditions = {k: v for k, v in rule.items() if k != "tier"}
            if all(facts.get(k) in v for k, v in conditions.items()):
                tier = rule["tier"]
                break
        editable = e.get("editable", tier in ("A", "B"))
        if tier == "C":
            editable = False
        return Tier(tier, bool(editable), e.get("label") or dotted, e.get("help") or "",
                    e.get("owner") or "")

    def fields(self, cfg: dict) -> list[tuple[str, object]]:
        """Every setting in a config, as (dotted path, value). Lists, and maps marked whole, are
        one setting each; other maps are walked into."""
        out: list[tuple[str, object]] = []

        def walk(node, prefix):
            for key, value in node.items():
                dotted = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(value, dict) and not self.is_whole(dotted):
                    walk(value, dotted)
                else:
                    out.append((dotted, value))

        walk(cfg, "")
        return out

    def missing_required(self, cfg: dict, present: set[str]) -> list[tuple[str, object]]:
        """Tier A settings that apply to this app but aren't in its file, as (dotted path, empty
        value). Without them the settings page can't ask for a required answer (QA-3)."""
        out: list[tuple[str, object]] = []
        for path, e in self.entries.items():
            if e.get("prefix") or e.get("whole") or path in present:
                continue
            if any(p.startswith(path + ".") or path.startswith(p + ".") for p in present):
                continue
            tier = self.resolve(path, cfg)
            if tier.tier == "A" and tier.editable:
                out.append((path, [] if e.get("kind") == "list" else ""))
        return out
