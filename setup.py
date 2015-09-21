#!/usr/bin/env python3

import os

from setuptools import setup, find_packages

__author__ = "Chelsea Urquhart"
__copyright__ = "Copyright 2015, Chelsea Urquhart"
__credits__ = []
__license__ = "mit"
__maintainer__ = "Chelsea Urquhart"
__email__ = "me@chelseau.com"
__status__ = "Beta"

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.md')) as f:
    CHANGES = f.read()

requires = [
    'Flask==0.10.1',
    'Github-Flask==3.0.1'
]

setup(
    name='Build Tester',
    version="1.0.0",
    author=__author__,
    author_email='me@chelseau.com',
    description='A simple server for tracking build pushes to GitHub, testing '
                'them, and sending status updates to GitHub.',
    license='MIT',
    keywords='git ',
    url='https://github.com/chelseau/buildtester',
    packages=find_packages(),
    long_description=README + "\n\n" + CHANGES,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Servers",
        "Framework :: Flask",
    ],
    install_requires=requires,
    entry_points="""\
    [console_scripts]
    serve = buildtester:main
    """,
)
