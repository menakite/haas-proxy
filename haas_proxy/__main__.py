"""
Entry script for the proxy. Twisted needs configured PYTHONPATH to properly
load all 3rd party plugins. This entry script simplifies it little bit.
"""

import os
import sys

from twisted.scripts.twistd import run

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
run()
