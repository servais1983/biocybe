"""Journalisation BioCybe.

Les loggers stdlib existants restent la source de vérité. Le format est
choisi par l'environnement, jamais par une valeur en dur dans le code :

- ``BIOCYBE_LOG_FORMAT=text`` (défaut) : lignes lisibles pour un humain.
- ``BIOCYBE_LOG_FORMAT=json`` : une ligne JSON par événement (SIEM).
  ``python-json-logger`` formate les loggers stdlib ; ``structlog`` est
  configuré sur la même sortie pour le code qui l'utilise directement.
- ``BIOCYBE_LOG_LEVEL`` : DEBUG, INFO, WARNING, ERROR, CRITICAL.
- ``BIOCYBE_LOG_FILE`` : chemin du fichier (défaut ``biocybe.log``).
  Vide pour désactiver le fichier. Un chemin non inscriptible est ignoré
  (conteneur read-only) : stderr reste disponible.
"""

from __future__ import annotations

import logging
import os
import sys

_TEXT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def log_level() -> int:
    name = os.environ.get("BIOCYBE_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, name, None)
    return level if isinstance(level, int) else logging.INFO


def log_format_name() -> str:
    name = os.environ.get("BIOCYBE_LOG_FORMAT", "text").strip().lower()
    return "json" if name == "json" else "text"


def build_formatter() -> logging.Formatter:
    """Formatter stdlib aligné sur ``BIOCYBE_LOG_FORMAT``."""
    if log_format_name() == "json":
        from pythonjsonlogger.json import JsonFormatter

        return JsonFormatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s",
            rename_fields={"asctime": "timestamp", "levelname": "level", "name": "logger"},
            timestamp=True,
        )
    return logging.Formatter(_TEXT_FORMAT)


def configure_structlog() -> None:
    """Aligne structlog sur le format choisi, via le logging stdlib."""
    import structlog

    if log_format_name() == "json":
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )


def default_log_handlers() -> list[logging.Handler]:
    """stderr + fichier optionnel. Ne lève pas si le fichier est impossible."""
    formatter = build_formatter()
    stderr = logging.StreamHandler()
    stderr.setFormatter(formatter)
    handlers: list[logging.Handler] = [stderr]
    log_file = os.environ.get("BIOCYBE_LOG_FILE", "biocybe.log")
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"biocybe: log fichier désactivé ({log_file}: {exc})\n")
        else:
            file_handler.setFormatter(formatter)
            handlers.append(file_handler)
    return handlers


def configure_logging(*, force: bool = False) -> None:
    """Configure le logger racine une fois (ou de force si ``force``)."""
    configure_structlog()
    root = logging.getLogger()
    level = log_level()
    if root.handlers and not force:
        root.setLevel(level)
        return
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    for handler in default_log_handlers():
        root.addHandler(handler)
    root.setLevel(level)
