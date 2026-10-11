"""Load and validate YAML/JSON playbook files from disk."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.playbooks.models import Playbook

logger = logging.getLogger(__name__)

_SUFFIXES = {".yml", ".yaml", ".json"}


class PlaybookLoadError(Exception):
    pass


def load_playbook_file(path: Path) -> Playbook:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
        return Playbook.model_validate(data)
    except (ValidationError, yaml.YAMLError, json.JSONDecodeError) as exc:
        raise PlaybookLoadError(f"{path.name}: {exc}") from exc


def load_playbooks(directory: Path) -> list[Playbook]:
    if not directory.is_dir():
        raise PlaybookLoadError(f"playbook directory not found: {directory}")
    playbooks: list[Playbook] = []
    seen: set[str] = set()
    for path in sorted(directory.iterdir()):
        if path.suffix not in _SUFFIXES:
            continue
        playbook = load_playbook_file(path)
        if playbook.id in seen:
            raise PlaybookLoadError(f"duplicate playbook id '{playbook.id}' in {path.name}")
        seen.add(playbook.id)
        playbooks.append(playbook)
        logger.info("loaded playbook %s (enabled=%s) from %s",
                    playbook.id, playbook.enabled, path.name)
    return playbooks
