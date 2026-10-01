# Allows running the auditor with python -m mcp_config_audit.

import sys

from .cli import main

sys.exit(main())
