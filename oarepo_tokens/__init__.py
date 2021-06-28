# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OArepo module that adds support for tokens"""

from .ext import OARepoTokens
from .version import __version__

__all__ = ('__version__', 'OARepoTokens')
