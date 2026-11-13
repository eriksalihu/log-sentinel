"""Allow `python -m log_sentinel` to start the command-line tool."""
import sys

from .cli import main

sys.exit(main())
