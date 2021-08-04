# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OARepo-Tokens permissions."""
import time

from flask import request
from invenio_records_rest.utils import allow_all, deny_all
from oarepo_fsm.permissions import require_any, require_all

from oarepo_tokens.views import get_token_from_headers, check_token_with_record
from oarepo_tokens.constants import INVALID_TOKEN_SLEEP


def token_permission_impl():
    """ Load token from request and check it for validity """
    def inner(record, *args, **kwargs):
        token_string = get_token_from_headers(request)
        if check_token_with_record(token_string, record):
            return allow_all
        else:
            time.sleep(INVALID_TOKEN_SLEEP)
            return deny_all

    return inner


def token_permission_factory(record, *args, **kwargs):
    return token_permission_impl()(record, *args, **kwargs)


def put_file_token_permission_factory(default_permission_factory):
    """Upload file permissions factory. Allow upload by token.

       Permission is granted if:
       * User have permission from default_permission_factory
       OR
       * Valid token used
    """

    def factory(record, *args, **kwargs):
        return require_any(
            default_permission_factory(record, *args, **kwargs),
            token_permission_factory(record, *args, **kwargs)
        )(record, *args, **kwargs)
    return factory
