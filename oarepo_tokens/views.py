# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OARepo-Tokens views."""

import json
import time
from datetime import datetime

from flask import Blueprint, jsonify, request, make_response, abort, url_for
from flask.views import MethodView
from werkzeug.utils import import_string
from invenio_records_rest.views import pass_record, need_record_permission
from invenio_records_rest.utils import deny_all, allow_all
from oarepo_actions.decorators import action

from oarepo_tokens.models import OARepoAccessToken
from oarepo_tokens.constants import INVALID_TOKEN_SLEEP, CREATE_TOKEN_PERMISSION


def json_abort(status_code, detail):
    detail['status'] = status_code
    abort(make_response(json.dumps(detail, indent=4, ensure_ascii=False), status_code))


def get_token_from_headers(request):
    headers = request.headers
    auth_header = headers.get('Authorization')
    token_string = auth_header.split(" ")[1] if auth_header else ''
    return token_string


def check_token_with_record(token_string, record):
    try:
        token = OARepoAccessToken.get_by_token(token_string)
    except:
        return False
    try:
        if token.rec_uuid == record.id and token.is_valid():
            return True
        return False
    except Exception as e:
        json_abort(500, {"message": f"Error: {e}"})


blueprint = Blueprint(
    'oarepo_tokens',
    __name__,
    url_prefix='/access-tokens'
)


@blueprint.route('/')
def token_list():
    """Access tokens list view."""
    tokens = OARepoAccessToken.query.all()
    return jsonify({'tokens': [{'id': token.id,
                                'repr': token.__repr__(),
                                'status': token.get_status(),
                                } for token in tokens]})


@blueprint.route('/<token_id>', strict_slashes=False)
def token_detail(token_id):
    """Access token detail."""
    token = OARepoAccessToken.get(token_id)
    if token:
        return jsonify({
            'links': token_links_factory(token),
            # 'token': token.token,
            'repr': token.__repr__(),
            'status': token.get_status(),
        })
    json_abort(404, {
        "message": "token %s was not found" % token_id
    })


def token_links_factory(token):
    """Links factory for token views."""
    rec = token.get_record()
    links = dict(
        token_detail=url_for('oarepo_tokens.token_detail', token_id=token.id, _external=True),
    )
    if rec is not None:
        links['init_upload'] = rec['init_upload']
        links['files'] = rec['files']
    return links


@blueprint.route('/status', strict_slashes=False)
def token_header_status():
    """token test"""
    token_string = get_token_from_headers(request)
    try:
        token = OARepoAccessToken.get_by_token(token_string)
    except:
        time.sleep(INVALID_TOKEN_SLEEP)
        json_abort(401, {"message": f"Invalid token. ({token_string})"})
    return jsonify({
        **token.to_json(filter_out=['token']),
        # 'token': token_string,
        'links': token_links_factory(token),
        'status': token.get_status(),
    })


@blueprint.route('/cleanup', strict_slashes=False)
def tokens_cleanup():
    """remove expired tokens - could be scheduled task only, not API method"""
    dt_now = datetime.utcnow()
    OARepoAccessToken.delete_expired(dt_now)
    return token_list()


@blueprint.route('/revoke', strict_slashes=False)
def revoke_token():
    """revoke token"""
    token_string = get_token_from_headers(request)
    try:
        token = OARepoAccessToken.get_by_token(token_string)
        assert token.is_valid()
    except:
        time.sleep(INVALID_TOKEN_SLEEP)
        json_abort(401, {"message": f"Invalid token. ({token_string})"})
    token.revoke()
    return jsonify({
        **token.to_json(filter_out=['token']),
        'token': token_string,
        'status': token.get_status(),
    })


class TokenEnabledDraftRecordMixin:

    @action(detail=True, url_path='create_token', method='post', permissions=CREATE_TOKEN_PERMISSION)
    def create_token(self, record=None, *args, **kwargs):
        token = OARepoAccessToken.create(self.id)
        rec = token.get_record()
        return jsonify({
            **token.to_json(),
            'links': token_links_factory(token),
        })

