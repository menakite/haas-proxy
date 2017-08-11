"""
Useful functions used by HaaS proxy.
"""

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
