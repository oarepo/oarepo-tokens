# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""Module tests."""
import six
from datetime import datetime, timedelta
from invenio_base.utils import load_or_import_from_config
# from invenio_db import db
from oarepo_tokens.models import OARepoAccessToken
from oarepo_tokens.views import check_token_with_record
from .helpers import make_sample_token, TestRecord

def _check_token(oartoken, draft_record):
    assert oartoken.rec_uuid == draft_record.id
    assert isinstance(oartoken.token, six.string_types)
    assert isinstance(oartoken.not_after, datetime)


def test_token_model(oartoken, draft_record):
    """Test OARepo token model."""
    _check_token(oartoken, draft_record)


def Xtest_token_create(draft_record):
    oartoken = make_sample_token(draft_record.id)
    _check_token(oartoken, draft_record)


def test_token_get(oartoken, draft_record):
    tok = OARepoAccessToken.get(oartoken.id)
    assert tok is not None
    _check_token(tok, draft_record)


def test_get_by_uuid(oartoken, draft_record):
    tok = OARepoAccessToken.get_by_uuid(draft_record.id)
    assert tok is not None
    _check_token(tok, draft_record)


def test_get_by_token(oartoken, draft_record):
    tok = OARepoAccessToken.get_by_token(oartoken.token)
    assert tok is not None
    _check_token(tok, draft_record)


def test_check_token(oartoken, draft_record):
    tok = OARepoAccessToken.get_by_token(oartoken.token)
    assert isinstance(tok, OARepoAccessToken)
    _check_token(tok, draft_record)
    assert tok.token == oartoken.token
    assert tok.is_valid()
    assert tok.rec_uuid == draft_record.id
    assert check_token_with_record(tok.token, draft_record) == True
    assert isinstance(draft_record, TestRecord)
    assert draft_record['id'] == '1'
    rec = tok.get_record()
    assert rec.id == draft_record.id
    assert rec['title']['en'] == "example draft record"
    assert 'init_upload' in rec

def test_query_expired_delete_expired(oartoken, draft_record):
    ttl = load_or_import_from_config('OAREPO_TOKENS_TOKEN_TTL')
    assert isinstance(ttl, six.integer_types)
    future_datetime = datetime.utcnow()+timedelta(seconds=ttl*2)
    toks = OARepoAccessToken.query_expired(future_datetime)
    assert len(toks) == 1
    assert isinstance(toks, list)
    _check_token(toks[0], draft_record)
    OARepoAccessToken.delete_expired(future_datetime)
    toks = OARepoAccessToken.query_expired(future_datetime)
    assert len(toks) == 0
    assert isinstance(toks, list)


# def test_token_delete(oartoken):
#     toks = OARepoAccessToken.query.all()
#     assert len(toks) == 1
#     db.session.delete(toks[0])
#     db.session.commit()
#     toks = OARepoAccessToken.query.all()
#     assert len(toks) == 0
