"""Allow ``python -m devsecops_scanner``."""

import sys

from devsecops_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
