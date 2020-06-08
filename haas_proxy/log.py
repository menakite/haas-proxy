"""
Log utilities.
"""

import logging


def init_python_logging(filename=None, level=None):
    """
    Starts Twisted observer sending all log messages to Python
    logging system and makes basic configuration as file name
    and log level.
    """

    logging.basicConfig(
        filename=filename,
        level={
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'debug': logging.DEBUG,
        }.get(level, logging.INFO),
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )
