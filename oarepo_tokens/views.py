# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OARepo-Tokens views."""

import json
from datetime import datetime

from flask import Blueprint, jsonify, request, make_response, abort, url_for
from flask.views import MethodView
from werkzeug.utils import import_string
from invenio_records_rest.views import pass_record, need_record_permission

from oarepo_tokens.models import OARepoAccessToken


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
        json_abort(401, {"message": f"Invalid token. ({token_string})"})
    return jsonify({
        **token.to_json(filter_out=['token']),
        # 'token': token_string,
        'links': token_links_factory(token),
        'status': token.get_status(),
    })


@blueprint.route('/cleanup', strict_slashes=False)
def tokens_cleanup():
    """remove expired tokens"""
    dt_now = datetime.utcnow()
    OARepoAccessToken.delete_expired(dt_now)
    return token_list()


class AccessTokenAction(MethodView):
    view_name = '{endpoint}_access_token'

    @pass_record
    # @need_record_permission('update_permission_factory_imp')
    def post(self, pid, record):
        token = OARepoAccessToken.create(record.id)
        rec = token.get_record()
        return jsonify({
            **token.to_json(),
            'links': token_links_factory(token),
            # 'links': {
                # 'create_token': url_for('oarepo_records_draft.draft-record_access_token', rec_uuid=record.id,
                #                         _external=True),
            # }
        })


def action_factory(code, files, rest_endpoint, extra, is_draft):
    return {
        'create_token': AccessTokenAction.as_view(
            AccessTokenAction.view_name.format(endpoint=code)
        )
    }
