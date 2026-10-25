import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS_SRC = ROOT / "tests" / "src"

# Permitir que los módulos antiguos se encuentren
# como submódulos del paquete src.
import src

if str(TESTS_SRC) not in src.__path__:
    src.__path__.append(str(TESTS_SRC))