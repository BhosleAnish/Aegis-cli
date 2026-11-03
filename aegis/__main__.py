"""Enable ``python -m aegis`` as an alias for the ``aegis`` console script."""
from __future__ import annotations

import sys

from aegis.cli import main

if __name__ == "__main__":
    sys.exit(main())
