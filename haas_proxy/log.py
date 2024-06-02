"""
Log utilities.
"""

import logging
from logging.handlers import SysLogHandler


LOGGER = None

def init_python_logging(filename=None, level=None):
    """
    Starts Twisted observer sending all log messages to Python
    logging system and makes basic configuration as file name
    and log level.
    """

    global LOGGER  # pylint: disable=global-statement
    if LOGGER is not None:
        LOGGER.warning('Tried to setup logging, but logging is already configured')

    # our_level:twisted_level (f.e. "debug:info")
    levels = level.split(':')
    if len(levels) == 1:
        levels = [level, None]

    log_levels = [{
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'debug': logging.DEBUG
    }.get(level, logging.INFO) for level in levels]

    if filename == 'syslog':
        handler = SysLogHandler(address='/dev/log', facility=SysLogHandler.LOG_DAEMON)
        logging.basicConfig(
            format='%(name)s: %(message)s',
            handlers=(handler,))
    else:
        logging.basicConfig(
            filename=filename,
            format='%(asctime)s %(levelname)s %(name)s %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S')

    LOGGER = logging.getLogger('haas-proxy')
    LOGGER.setLevel(log_levels[0])

    # Set Twisted log level, if asked to do so
    if levels[1] is not None:
        logging.getLogger('twisted').setLevel(log_levels[1])

def get_logger():
    global LOGGER  # pylint: disable=global-variable-not-assigned
    return LOGGER
