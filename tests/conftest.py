import sys
from pathlib import Path

# Los modulos usan imports absolutos (core, modules), asi que app/ va al path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
