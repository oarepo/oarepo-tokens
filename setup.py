# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OArepo module that adds support for tokens"""

import os

from setuptools import find_packages, setup

readme = open('README.md').read()
history = open('CHANGES.rst').read()

OAREPO_VERSION = os.environ.get('OAREPO_VERSION', '3.3.0')

tests_require = [
    'pydocstyle',
    'isort',
    'oarepo_records_draft',
    'oarepo_validate',
    'oarepo_references',
    'oarepo_fsm',
    'oarepo_multilingual',
    'moto',
    'oarepo-s3',
    'oarepo-actions',
]

extras_require = {
    'tests': [
        'oarepo[tests]~={version}'.format(version=OAREPO_VERSION),
        *tests_require
    ]
}

extras_require['all'] = []
for reqs in extras_require.values():
    extras_require['all'].extend(reqs)

setup_requires = [
]

install_requires = [
]

packages = find_packages()

# Get the version string. Cannot be done with import!
g = {}
with open(os.path.join('oarepo_tokens', 'version.py'), 'rt') as fp:
    exec(fp.read(), g)
    version = g['__version__']

setup(
    name='oarepo-tokens',
    version=version,
    description=__doc__,
    long_description=readme + '\n\n' + history,
    keywords='invenio oarepo tokens',
    long_description_content_type='text/markdown',
    license='MIT',
    author='Tomas Hlava',
    author_email='hlava@cesnet.cz',
    url='https://github.com/oarepo/oarepo-tokens',
    packages=packages,
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    entry_points={
#        'flask.commands': [
#            'oarepo:tokens = oarepo_tokens.cli:tokens',
#        ],
        'invenio_base.apps': [
            'oarepo_tokens = oarepo_tokens:OARepoTokens',
        ],
        'invenio_base.api_apps': [
            'oarepo_tokens = oarepo_tokens:OARepoTokens',
        ],
        'invenio_base.api_blueprints': [
            'oarepo_tokens = oarepo_tokens.views:blueprint',
        ],
        'invenio_db.models': [
            'oarepo_tokens = oarepo_tokens.models',
        ],
        'invenio_db.alembic': [
            'oarepo_tokens = oarepo_tokens:alembic',
        ],
        # 'oarepo_records_draft.extra_actions': [
        #     'oarepo_tokens = oarepo_tokens.views:action_factory',
        # ],
    },
    extras_require=extras_require,
    install_requires=install_requires,
    setup_requires=setup_requires,
    tests_require=tests_require,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Development Status :: 1 - Planning',
    ],
)
