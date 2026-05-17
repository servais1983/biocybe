"""conftest.py racine : permet aux tests de trouver le package `biocybe`
sans nécessiter `pip install -e .` au préalable.

Ajoute `src/` à `sys.path` avant que pytest collecte les tests.
"""

import sys
from pathlib import Path

SRC = Path(__file__).parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
