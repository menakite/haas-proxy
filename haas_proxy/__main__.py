"""
Entry script for the proxy. Twisted needs configured PYTHONPATH to properly
load all 3rd party plugins. This entry script simplifies it little bit.
"""

import os
import sys

from twisted.application import app
from twisted.logger import STDLibLogObserver
from twisted.scripts.twistd import ServerOptions, runApp

sys.path.append(os.path.dirname(os.path.realpath(__file__)))


def wrapped_run(config):
    """ Runs twisted with default `--logger` arg overriden """
    if config.get("logger") is None:
        config["logger"] = STDLibLogObserver
    runApp(config)


app.run(wrapped_run, ServerOptions)
