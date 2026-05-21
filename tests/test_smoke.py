"""Smoke tests : vérifient que les imports et l'initialisation de base passent.

Ces tests ne valident pas la logique métier, juste que le système
n'est pas cassé au niveau structurel (imports, classes accessibles,
core instanciable).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def test_import_biocybe_package():
    import biocybe

    assert biocybe.__version__
    # La version du package doit être alignée avec pyproject (0.2.x)
    assert biocybe.__version__.startswith("0.2")


def test_heritage_modules_import_without_heavy_deps():
    """Les modules héritage ne doivent plus crasher l'import (deps lazy).

    Régression : avant le nettoyage, `import biocybe.swarm_intelligence`
    exigeait numpy+networkx au niveau module, et
    `import biocybe.learning.reinforcement_learning` exigeait TensorFlow.
    Désormais l'import passe ; les deps ne sont requises qu'à l'usage.
    """
    import importlib

    # Ne doivent PAS lever ImportError au simple import (deps lazy/guardées)
    for mod in (
        "biocybe.swarm_intelligence",
        "biocybe.learning.reinforcement_learning",
        "biocybe.explainability",
        "biocybe.detection.signature_detector",
    ):
        importlib.import_module(mod)


def test_import_core():
    from biocybe.biocybe_core import BioCybeCore, BiologicalCell, CellMessage

    assert BioCybeCore and BiologicalCell and CellMessage


def test_import_macrophages():
    from biocybe.macrophages import MacrophageCell, create_cells

    assert MacrophageCell and create_cells


def test_import_lymphocytes_b():
    from biocybe.lymphocytes_b import BCell, create_cells

    assert BCell and create_cells


def test_isolation_stub_raises():
    import pytest

    from biocybe.isolation import isolate

    with pytest.raises(NotImplementedError):
        isolate("dummy")


def test_neutralization_stub_raises():
    import pytest

    from biocybe.neutralization import neutralize

    with pytest.raises(NotImplementedError):
        neutralize("dummy")


def test_core_instantiable():
    from biocybe.biocybe_core import BioCybeCore

    core = BioCybeCore()
    assert core is not None
    assert hasattr(core, "register_cell")
    assert hasattr(core, "start")
    assert hasattr(core, "stop")


def test_cellmessage_roundtrip():
    from biocybe.biocybe_core import CellMessage

    msg = CellMessage(msg_type="alert", source="test", payload={"x": 1})
    d = msg.to_dict()
    assert d["type"] == "alert"
    assert d["source"] == "test"
    assert d["payload"] == {"x": 1}
