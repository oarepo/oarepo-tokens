# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""Module tests."""

from flask import Flask

from oarepo_tokens import OARepoTokens


def test_version():
    """Test version import."""
    from oarepo_tokens import __version__
    assert __version__


def test_init():
    """Test extension initialization."""
    app = Flask('testapp')
    ext = OARepoTokens(app)
    assert 'oarepo-tokens' in app.extensions

    app = Flask('testapp')
    ext = OARepoTokens()
    assert 'oarepo-tokens' not in app.extensions
    ext.init_app(app)
    assert 'oarepo-tokens' in app.extensions

