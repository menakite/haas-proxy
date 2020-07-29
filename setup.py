#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

EXTRA_TEST_REQUIRE = [
    'pylint',
    'pytest',
]

setup(
    name='haas-proxy',
    version='2.0.2',
    packages=[
        'haas_proxy',
        'haas_proxy.twisted.plugins',
    ],

    install_requires=[
        'twisted[conch]>=16.6',
        'requests',
        'cachetools',
    ],
    extras_require={
        'test': [
            'pylint',
            'pytest',
        ],
    },

    url='https://haas.nic.cz',
    author='CZ.NIC Labs',
    author_email='haas@nic.cz',
    description='Honeypot proxy is tool for redirectiong SSH session from local computer to server of HaaS with additional information.',
    license='GPLv3',

    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
    ],
)
