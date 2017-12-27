import logging

from twisted.python import log


def init_python_logging(filename, level):
    observer = log.PythonLoggingObserver()
    observer.start()

    logging.basicConfig(
        filename=filename,
        level={
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'debug': logging.DEBUG,
        }.get(level, logging.INFO),
    )
