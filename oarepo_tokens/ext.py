# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OArepo module that adds support for tokens"""

from . import config


class OARepoTokens(object):
    """OARepo-Tokens extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        self.init_config(app)

        app.extensions['oarepo-tokens'] = self

    def init_config(self, app):
        """Initialize configuration."""
        # Use theme's base template if theme is installed

        for k in dir(config):
            if k.startswith('OAREPO_TOKENS_'):
                app.config.setdefault(k, getattr(config, k))
