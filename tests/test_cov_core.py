"""Couverture du noyau cellulaire. Threads arrêtés dans le test, aucun réseau."""

from __future__ import annotations

import logging
import threading
import time
import types
from datetime import datetime, timedelta

import yaml

import biocybe.biocybe_core.core as coremod
from biocybe.biocybe_core.core import BioCybeCore, BiologicalCell, CellMessage


def test_messages_and_cell_lifecycle():
    early = CellMessage("ping", "a", priority=0, timestamp=datetime.now() - timedelta(seconds=5))
    late = CellMessage("pong", "b", target="solo", priority=9, timestamp=datetime.now())
    assert early.priority == 1 and late.priority == 5
    assert str(late).startswith("Message[")
    assert early < late
    assert "type" in late.to_dict()

    cell = BiologicalCell("solo", "lab", {"tick_interval": 0.05})
    assert cell.send_message("x") is False
    assert cell.handle_message(CellMessage("nope", "other")) is False

    def boom(_message):
        raise RuntimeError("handler")

    cell.register_message_handler("boom", boom)
    assert cell.handle_message(CellMessage("boom", "other")) is False
    cell.register_message_handler("ok", lambda _m: True)
    assert cell.handle_message(CellMessage("ok", "other")) is True
    idle = BiologicalCell("idle", "lab")
    idle.stop()
    assert cell.get_status()["name"] == "solo"
    cell.start()
    cell.start()
    time.sleep(0.1)
    cell.stop()
    if cell._worker_thread.is_alive():
        cell._worker_thread.join(timeout=2)

    class BoomCell(BiologicalCell):
        def _process_cycle(self):
            raise RuntimeError("cycle")

    broken = BoomCell("broken", "lab", {"tick_interval": 0.05})
    broken.start()
    time.sleep(0.15)
    if broken._worker_thread.is_alive():
        broken.stop()
        broken._worker_thread.join(timeout=2)


def test_core_bus_and_persistence(tmp_path, monkeypatch):
    missing = BioCybeCore(str(tmp_path / "absent.yaml"))
    assert "core" in missing.config
    not_map = tmp_path / "list.yaml"
    not_map.write_text("[]\n", encoding="utf-8")
    assert "cells" in BioCybeCore(str(not_map)).config
    good = tmp_path / "ok.yaml"
    good.write_text(yaml.safe_dump({"core": {"log_level": "INFO"}}), encoding="utf-8")
    core = BioCybeCore(str(good))

    a = BiologicalCell("a", "lab", {"tick_interval": 0.05})
    b = BiologicalCell("b", "lab", {"tick_interval": 0.05})
    assert core.register_cell(a) is True
    assert core.register_cell(a) is False
    assert core.register_cell(b) is True
    a.send_message("alert_lab", target="broadcast", payload={"n": 1}, priority=3)
    a.send_message("note", target="type:lab", payload={})
    a.send_message("note", target="b")
    a.send_message("note", target="missing")
    core._dispatch_message(CellMessage("note", "a", target="type:nope"))

    fresh = BioCybeCore(str(good))
    fresh.stop()
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    core.start()
    core.start()
    threading.Event().wait(0.7)
    core.stats["start_time"] = "not-a-datetime"
    status = core.get_status()
    assert status["core"]["uptime"] == 0.0
    core.stats["start_time"] = datetime.now()
    assert core.get_status()["core"]["uptime"] >= 0
    saved = tmp_path / "state" / "status.json"
    assert core.save_status(str(saved)) is True
    assert core.save_status(str(tmp_path)) is False

    def crash(_message):
        raise RuntimeError("dispatch")

    core._dispatch_message = crash
    core.stop()

    held = BioCybeCore(str(good))
    held.start()
    threading.Event().wait(0.1)
    assert held._message_thread.is_alive()
    held.stop()

    class _Flaky:
        def __init__(self):
            self._real = threading.Event()
            self.calls = 0

        def is_set(self):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("critical")
            return self._real.is_set()

        def set(self):
            self._real.set()

    flaky = BioCybeCore(str(good))
    flaky._stop_event = _Flaky()
    flaky.start()
    threading.Event().wait(0.3)
    flaky._stop_event.set()
    flaky._message_thread.join(timeout=2)

    def fake_import(name):
        if name == "biocybe.cells":
            mod = types.ModuleType(name)
            mod.__path__ = ["."]
            return mod
        if name.endswith(".good"):
            mod = types.ModuleType(name)
            mod.create_cells = lambda _cfg: [
                BiologicalCell("frommod", "loaded", {"tick_interval": 1})
            ]
            return mod
        if name.endswith(".bad"):
            raise RuntimeError("module")
        if name.endswith(".plain"):
            return types.ModuleType(name)
        raise ImportError(name)

    monkeypatch.setattr(coremod.importlib, "import_module", fake_import)
    monkeypatch.setattr(
        coremod.pkgutil,
        "iter_modules",
        lambda *_a, **_k: [
            (None, "biocybe.cells.good", True),
            (None, "biocybe.cells.bad", True),
            (None, "biocybe.cells.plain", True),
            (None, "biocybe.cells.skip", False),
        ],
    )
    core.load_cells_from_modules()
    assert "frommod" in core.cells

    def fail_import(_name):
        raise ImportError("no package")

    monkeypatch.setattr(coremod.importlib, "import_module", fail_import)
    core.load_cells_from_modules("biocybe.missing_cells")


def test_logging_bootstrap(monkeypatch):
    root = logging.getLogger()
    saved = list(root.handlers)
    level = root.level
    for handler in saved:
        root.removeHandler(handler)
    import importlib

    import biocybe.biocybe_core.core as core

    importlib.reload(core)
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    for handler in saved:
        root.addHandler(handler)
    root.setLevel(level)
    assert core._default_log_handlers()
    assert core.CellMessage is not None
