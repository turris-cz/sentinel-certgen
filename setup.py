#!/usr/bin/env python

import os
from setuptools import setup

from certgen import __version__


def get_description(filename):
    """Reads and returns content of given file
    """
    with open(os.path.join(os.path.dirname(__file__), filename)) as f:
        return f.read()


setup(
        name='certgen',
        packages=[
                'certgen',
        ],
        version=__version__,
        description='Client application for automated passwords and certificates retrieval',
        long_description=get_description('README.md'),
        long_description_content_type='text/markdown',
        url='https://gitlab.labs.nic.cz/turris/sentinel/certgen',
        author='CZ.NIC, z.s.p.o.',
        author_email='packaging@turris.cz',
        license='GNU GPL v3',
        install_requires=[
                'cryptography',
                'requests',
        ],
        entry_points={
            'console_scripts': [
                'sentinel-certgen=certgen.__main__:main'
            ]
        },
)
