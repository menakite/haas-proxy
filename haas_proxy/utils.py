"""
Useful functions used by HaaS proxy.
"""

import os
import shutil


def force_text(value):
    """
    Helper to deal with bytes and str in Python 2 vs. Python 3. Needed to have
    always username and password as a string (i Python 3 it's bytes).
    """
    if issubclass(type(value), str):
        return value
    if isinstance(value, bytes):
        return str(value, 'utf-8')
    return str(value)


def which(cmd, mode=os.F_OK | os.X_OK, path=None) -> str:
    """ Wrapper around shutils.which
    if the required command is not found it raises an Exception
    """

    res = shutil.which(cmd, mode, path)
    if res is None:
        raise RuntimeError(f"{cmd} was not found in PATH")

    return res
