#!/usr/bin/env python

import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


# You need at least Twisted version 16.0 but version for Python 3
# has some bugs which are solved in 16.6.
TWISTED_VERSION = '16.0' if sys.version_info < (3, 0) else '16.6'

EXTRA_TEST_REQUIRE = [
    'pylint',
    'pytest',
]
if sys.version_info < (3, 0):
    EXTRA_TEST_REQUIRE += ['mock']


setup(
    name='haas-proxy',
    version='1.9',
    packages=[
        'haas_proxy',
        'haas_proxy.twisted.plugins',
    ],

    install_requires=[
        'twisted[conch]>={}'.format(TWISTED_VERSION),
        'requests',
        'cachetools',
    ],
    extras_require={
        'test': EXTRA_TEST_REQUIRE,
    },

    url='https://haas.nic.cz',
    author='CZ.NIC Labs',
    author_email='haas@nic.cz',
    description='Honeypot proxy is tool for redirectiong SSH session from local computer to server of HaaS with additional information.',
    license='GPLv3',

    classifiers=[
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
    ],
)
